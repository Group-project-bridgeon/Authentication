package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
)

type mockPermissionQuerier struct {
	fn func(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error)
}

func (m *mockPermissionQuerier) GetUserGlobalPermissions(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error) {
	if m.fn != nil {
		return m.fn(ctx, userID)
	}
	return nil, nil
}

func TestPermissionRepo_GetGlobalPermissions_Mapping(t *testing.T) {
	targetUserID := uuid.New()
	querierCalled := false

	mockQ := &mockPermissionQuerier{
		fn: func(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error) {
			if userID != targetUserID {
				t.Fatalf("expected userID %s, got %s", targetUserID, userID)
			}
			querierCalled = true
			return []sqlcdb.IdentityPermission{
				{
					ID:          uuid.New(),
					Resource:    "catalog",
					Action:      "read",
					Description: stringToPgText("Read catalog items"),
				},
				{
					ID:          uuid.New(),
					Resource:    "products",
					Action:      "write",
					Description: stringToPgText("Write products"),
				},
			}, nil
		},
	}

	repo := newPermissionRepoWithQuerier(mockQ)
	perms, err := repo.GetGlobalPermissions(context.Background(), targetUserID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !querierCalled {
		t.Fatal("expected querier to be called")
	}

	expected := []domain.Permission{
		{Resource: "catalog", Action: "read"},
		{Resource: "products", Action: "write"},
	}

	if !reflect.DeepEqual(perms, expected) {
		t.Fatalf("expected permissions %+v, got %+v", expected, perms)
	}
}

func TestPermissionRepo_GetGlobalPermissions_EmptyResult(t *testing.T) {
	testCases := []struct {
		name       string
		mockReturn []sqlcdb.IdentityPermission
	}{
		{
			name:       "nil slice returned from sqlc",
			mockReturn: nil,
		},
		{
			name:       "empty slice returned from sqlc",
			mockReturn: []sqlcdb.IdentityPermission{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockQ := &mockPermissionQuerier{
				fn: func(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error) {
					return tc.mockReturn, nil
				},
			}

			repo := newPermissionRepoWithQuerier(mockQ)
			perms, err := repo.GetGlobalPermissions(context.Background(), uuid.New())
			if err != nil {
				t.Fatalf("expected nil error for empty permissions, got: %v", err)
			}

			if perms == nil {
				t.Fatal("expected non-nil empty slice, got nil")
			}

			if len(perms) != 0 {
				t.Fatalf("expected 0 permissions, got: %d", len(perms))
			}
		})
	}
}

func TestPermissionRepo_GetGlobalPermissions_ErrorPropagation(t *testing.T) {
	dbErr := errors.New("simulated database failure")

	mockQ := &mockPermissionQuerier{
		fn: func(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error) {
			return nil, dbErr
		},
	}

	repo := newPermissionRepoWithQuerier(mockQ)
	perms, err := repo.GetGlobalPermissions(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, dbErr) {
		t.Fatalf("expected error %v, got %v", dbErr, err)
	}

	if perms != nil {
		t.Fatalf("expected nil permissions on error, got %+v", perms)
	}
}

func TestPermissionRepo_GetGlobalPermissions_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockQ := &mockPermissionQuerier{
		fn: func(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error) {
			return nil, ctx.Err()
		},
	}

	repo := newPermissionRepoWithQuerier(mockQ)
	perms, err := repo.GetGlobalPermissions(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	if perms != nil {
		t.Fatalf("expected nil permissions on context cancellation, got %+v", perms)
	}
}
