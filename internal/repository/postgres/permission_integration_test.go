package postgres

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPermissionRepo_GetGlobalPermissions_Integration(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL permission integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	// Run within a transaction that always rolls back to preserve table isolation
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// 1. Create Isolated Users
	userAID := uuid.New()
	userBID := uuid.New()
	userCID := uuid.New()

	for _, u := range []struct {
		id    uuid.UUID
		email string
		name  string
	}{
		{id: userAID, email: "perm-test-a-" + userAID.String() + "@example.com", name: "User A"},
		{id: userBID, email: "perm-test-b-" + userBID.String() + "@example.com", name: "User B"},
		{id: userCID, email: "perm-test-c-" + userCID.String() + "@example.com", name: "User C"},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity_users (id, email, full_name, is_active)
			VALUES ($1, $2, $3, true)
		`, u.id, u.email, u.name)
		if err != nil {
			t.Fatalf("insert user %s: %v", u.email, err)
		}
	}

	// 2. Create Permissions
	permCatalogReadID := uuid.New()
	permCatalogWriteID := uuid.New()
	permOrderCreateID := uuid.New()
	permWarehouseReadID := uuid.New()
	permUserBOnlyID := uuid.New()

	for _, p := range []struct {
		id       uuid.UUID
		resource string
		action   string
	}{
		{id: permCatalogReadID, resource: "catalog", action: "read"},
		{id: permCatalogWriteID, resource: "catalog", action: "write"},
		{id: permOrderCreateID, resource: "order", action: "create"},
		{id: permWarehouseReadID, resource: "warehouse", action: "read"},
		{id: permUserBOnlyID, resource: "analytics", action: "view"},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity_permissions (id, resource, action, description)
			VALUES ($1, $2, $3, $4)
		`, p.id, p.resource, p.action, "Integration test permission")
		if err != nil {
			t.Fatalf("insert permission %s:%s: %v", p.resource, p.action, err)
		}
	}

	// 3. Create Roles
	roleGlobal1ID := uuid.New()
	roleGlobal2ID := uuid.New()
	roleWarehouseID := uuid.New()
	roleUserBID := uuid.New()

	for _, r := range []struct {
		id   uuid.UUID
		name string
	}{
		{id: roleGlobal1ID, name: "role-global-1-" + roleGlobal1ID.String()[:8]},
		{id: roleGlobal2ID, name: "role-global-2-" + roleGlobal2ID.String()[:8]},
		{id: roleWarehouseID, name: "role-warehouse-" + roleWarehouseID.String()[:8]},
		{id: roleUserBID, name: "role-user-b-" + roleUserBID.String()[:8]},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity_roles (id, name, description, is_system)
			VALUES ($1, $2, $3, false)
		`, r.id, r.name, "Integration test role")
		if err != nil {
			t.Fatalf("insert role %s: %v", r.name, err)
		}
	}

	// 4. Assign Permissions to Roles
	// roleGlobal1 has catalog:read and catalog:write
	// roleGlobal2 has catalog:write (duplicate grant across global roles) and order:create
	// roleWarehouse has warehouse:read
	// roleUserB has analytics:view
	for _, rp := range []struct {
		roleID uuid.UUID
		permID uuid.UUID
	}{
		{roleID: roleGlobal1ID, permID: permCatalogReadID},
		{roleID: roleGlobal1ID, permID: permCatalogWriteID},
		{roleID: roleGlobal2ID, permID: permCatalogWriteID}, // duplicate
		{roleID: roleGlobal2ID, permID: permOrderCreateID},
		{roleID: roleWarehouseID, permID: permWarehouseReadID},
		{roleID: roleUserBID, permID: permUserBOnlyID},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity_role_permissions (role_id, permission_id)
			VALUES ($1, $2)
		`, rp.roleID, rp.permID)
		if err != nil {
			t.Fatalf("insert role_permission (%s, %s): %v", rp.roleID, rp.permID, err)
		}
	}

	// 5. Assign Roles to Users
	// User A: roleGlobal1 (GLOBAL), roleGlobal2 (GLOBAL), roleWarehouse (WAREHOUSE) -> mixed scopes
	// User B: roleUserB (GLOBAL)
	// User C: no roles assigned
	warehouseScopeID := uuid.New()

	for _, ur := range []struct {
		userID    uuid.UUID
		roleID    uuid.UUID
		scopeType string
		scopeID   *uuid.UUID
	}{
		{userID: userAID, roleID: roleGlobal1ID, scopeType: "GLOBAL", scopeID: nil},
		{userID: userAID, roleID: roleGlobal2ID, scopeType: "GLOBAL", scopeID: nil},
		{userID: userAID, roleID: roleWarehouseID, scopeType: "WAREHOUSE", scopeID: &warehouseScopeID},
		{userID: userBID, roleID: roleUserBID, scopeType: "GLOBAL", scopeID: nil},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity_user_roles (id, user_id, role_id, scope_type, scope_id)
			VALUES ($1, $2, $3, $4, $5)
		`, uuid.New(), ur.userID, ur.roleID, ur.scopeType, ur.scopeID)
		if err != nil {
			t.Fatalf("insert user_role (%s, %s, %s): %v", ur.userID, ur.roleID, ur.scopeType, err)
		}
	}

	repo := newPermissionRepo(tx)

	t.Run("Mixed scopes return only global role grants", func(t *testing.T) {
		perms, err := repo.GetGlobalPermissions(ctx, userAID)
		if err != nil {
			t.Fatalf("GetGlobalPermissions error: %v", err)
		}

		// Expected results:
		// 1. GLOBAL role grants returned (catalog:read, catalog:write, order:create)
		// 2. WAREHOUSE-only grants excluded (warehouse:read NOT returned)
		// 3. Duplicate permissions from multiple global roles appear once (catalog:write only once)
		// 4. Another user's assignments do not leak (analytics:view NOT returned)
		// 5. Results ordered by resource and action
		expected := []domain.Permission{
			{Resource: "catalog", Action: "read"},
			{Resource: "catalog", Action: "write"},
			{Resource: "order", Action: "create"},
		}

		if !reflect.DeepEqual(perms, expected) {
			t.Fatalf("expected permissions:\n%+v\ngot:\n%+v", expected, perms)
		}
	})

	t.Run("User with no role assignments receives zero permissions", func(t *testing.T) {
		perms, err := repo.GetGlobalPermissions(ctx, userCID)
		if err != nil {
			t.Fatalf("GetGlobalPermissions error: %v", err)
		}

		if perms == nil {
			t.Fatal("expected non-nil empty slice, got nil")
		}

		if len(perms) != 0 {
			t.Fatalf("expected 0 permissions for user with no assignments, got %d: %+v", len(perms), perms)
		}
	})

	t.Run("Another user assignments do not leak into target user result", func(t *testing.T) {
		permsB, err := repo.GetGlobalPermissions(ctx, userBID)
		if err != nil {
			t.Fatalf("GetGlobalPermissions error: %v", err)
		}

		expectedB := []domain.Permission{
			{Resource: "analytics", Action: "view"},
		}

		if !reflect.DeepEqual(permsB, expectedB) {
			t.Fatalf("expected permissions for User B:\n%+v\ngot:\n%+v", expectedB, permsB)
		}
	})
}
