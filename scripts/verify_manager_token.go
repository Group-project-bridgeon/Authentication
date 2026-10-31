package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/config"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/platform/database"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/service"
	"github.com/group-project/authentication/internal/service/dto"
)

type ManagerCustomClaims struct {
	jwt.RegisteredClaims
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	TokenVersion *int     `json:"token_version"`
	Permissions  []string `json:"permissions"`
}

func verifyManagerToken(tokenString string, pubKey *rsa.PublicKey, expectedIssuer, expectedAudience string) (*ManagerCustomClaims, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, fmt.Errorf("token string is blank")
	}

	var claims ManagerCustomClaims
	parsedToken, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithNotBeforeRequired(),
		jwt.WithLeeway(0),
	)

	if err != nil {
		return nil, fmt.Errorf("jwt.ParseWithClaims failed: %w", err)
	}

	if parsedToken == nil || !parsedToken.Valid {
		return nil, fmt.Errorf("parsed token is invalid")
	}

	// Validate lifetime: exp - iat must be > 0 and <= 15 minutes.
	if claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, fmt.Errorf("missing required timestamp claims (exp, iat, nbf)")
	}
	if !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return nil, fmt.Errorf("exp is not after iat")
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime > 15*time.Minute {
		return nil, fmt.Errorf("token lifetime %v exceeds 15 minutes", lifetime)
	}

	// Validate user_id and sub match.
	if claims.UserID == "" || claims.Subject == "" || claims.UserID != claims.Subject {
		return nil, fmt.Errorf("user_id (%q) does not equal sub (%q)", claims.UserID, claims.Subject)
	}
	if _, err := uuid.Parse(claims.UserID); err != nil {
		return nil, fmt.Errorf("user_id %q is not a valid UUID: %w", claims.UserID, err)
	}

	// Validate email.
	if claims.Email == "" {
		return nil, fmt.Errorf("email claim is empty")
	}

	// Validate token_version >= 0.
	if claims.TokenVersion == nil || *claims.TokenVersion < 0 {
		return nil, fmt.Errorf("token_version is nil or negative: %v", claims.TokenVersion)
	}

	// Validate permissions: must be present (non-nil, non-empty) and each entry must be "resource:action" (exactly one colon)
	if claims.Permissions == nil {
		return nil, fmt.Errorf("permissions slice is nil")
	}
	if len(claims.Permissions) == 0 {
		return nil, fmt.Errorf("permissions slice is empty")
	}
	for _, perm := range claims.Permissions {
		parts := strings.Split(perm, ":")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("malformed permission string: %q", perm)
		}
	}

	return &claims, nil
}

func main() {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://auth_service:change_me_auth_password@127.0.0.1:5432/auth_db?sslmode=disable"
	}

	keyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if keyPath == "" {
		keyPath = "keys/jwt-private.pem"
	}

	issuer := "erp-auth"
	audience := "erp-api"
	expiry := 15 * time.Minute

	privKey, err := helper.LoadRSAPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LoadRSAPrivateKey failed: %v\n", err)
		os.Exit(1)
	}

	jwtManager, err := helper.NewJWTManager(privKey, issuer, audience, expiry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewJWTManager failed: %v\n", err)
		os.Exit(1)
	}

	pool, err := database.NewPool(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database.NewPool failed: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	hasher := helper.NewBcrypt()
	hashedPassword, err := hasher.Hash("Password123!")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bcrypt hash failed: %v\n", err)
		os.Exit(1)
	}

	// 1. Seed Roles, Users, Role Permissions, and User Roles in auth_db
	tx, err := pool.Begin(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Begin transaction failed: %v\n", err)
		os.Exit(1)
	}
	defer tx.Rollback(ctx)

	// Roles
	_, err = tx.Exec(ctx, `
		INSERT INTO identity_roles (name, description, is_system)
		VALUES 
			('admin', 'Administrator with full manager permissions', false),
			('manager', 'Manager with workflow approval permissions', false)
		ON CONFLICT (name) DO NOTHING;
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Insert roles failed: %v\n", err)
		os.Exit(1)
	}

	// Role permissions: admin gets all 6 manager.* permissions
	_, err = tx.Exec(ctx, `
		INSERT INTO identity_role_permissions (role_id, permission_id)
		SELECT r.id, p.id
		FROM identity_roles r
		CROSS JOIN identity_permissions p
		WHERE r.name = 'admin'
		  AND p.resource IN ('manager.approvals', 'manager.rbac', 'manager.authz')
		ON CONFLICT (role_id, permission_id) DO NOTHING;
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Insert admin role permissions failed: %v\n", err)
		os.Exit(1)
	}

	// Role permissions: manager gets manager approval permissions
	_, err = tx.Exec(ctx, `
		INSERT INTO identity_role_permissions (role_id, permission_id)
		SELECT r.id, p.id
		FROM identity_roles r
		CROSS JOIN identity_permissions p
		WHERE r.name = 'manager'
		  AND p.resource = 'manager.approvals'
		ON CONFLICT (role_id, permission_id) DO NOTHING;
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Insert manager role permissions failed: %v\n", err)
		os.Exit(1)
	}

	// Create users
	usersToSeed := []struct {
		Email    string
		FullName string
		RoleName string
	}{
		{Email: "admin@erp.local", FullName: "Test Admin", RoleName: "admin"},
		{Email: "manager@erp.local", FullName: "Test Manager", RoleName: "manager"},
		{Email: "admin@example.com", FullName: "Test Admin Example", RoleName: "admin"},
		{Email: "manager@example.com", FullName: "Test Manager Example", RoleName: "manager"},
	}

	for _, u := range usersToSeed {
		var userID uuid.UUID
		err = tx.QueryRow(ctx, `
			INSERT INTO identity_users (email, full_name, is_active, token_version, email_verified_at)
			VALUES ($1, $2, true, 1, now())
			ON CONFLICT ((lower(email))) DO UPDATE SET is_active = true, email_verified_at = COALESCE(identity_users.email_verified_at, now())
			RETURNING id;
		`, u.Email, u.FullName).Scan(&userID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upsert user %s failed: %v\n", u.Email, err)
			os.Exit(1)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO identity_credentials (user_id, password_hash)
			VALUES ($1, $2)
			ON CONFLICT (user_id) DO UPDATE SET password_hash = $2;
		`, userID, hashedPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upsert credential %s failed: %v\n", u.Email, err)
			os.Exit(1)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO identity_user_roles (user_id, role_id, scope_type, scope_id)
			SELECT $1, r.id, 'GLOBAL', NULL
			FROM identity_roles r
			WHERE r.name = $2
			ON CONFLICT (user_id, role_id, scope_type, scope_id) DO NOTHING;
		`, userID, u.RoleName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Assign user role %s -> %s failed: %v\n", u.Email, u.RoleName, err)
			os.Exit(1)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Commit transaction failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Successfully seeded roles, permissions grants, and test users in auth_db.")

	// 2. Initialize Auth Service and log in as test admin and test manager
	usrRepo := postgres.NewUserRepo(pool)
	credentialRepo := postgres.NewCredentialRepo(pool)
	externalIdentityRepo := postgres.NewExternalIdentityRepo(pool)
	verificationRepo := postgres.NewVerificationRepo(pool)
	passwordResetRepo := postgres.NewPasswordResetRepo(pool)
	permissionRepo := postgres.NewPermissionRepo(pool)
	txManager := postgres.NewTransactionManager(pool)

	authSvc := service.NewAuthService(
		usrRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		passwordResetRepo,
		permissionRepo,
		txManager,
		hasher,
		jwtManager,
		helper.NewEmailSender(config.SMTPConfig{Host: "mock"}),
		helper.NewGoogleOAuthProvider(config.GoogleOAuthConfig{}),
	)

	// Log in as test admin
	adminLogin, err := authSvc.Login(ctx, dto.LoginInput{
		Email:    "admin@erp.local",
		Password: "Password123!",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Admin login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n[SUCCESS] Test Admin logged in successfully! UserID: %s\nToken: %s\n", adminLogin.User.ID, adminLogin.Token)

	// Log in as test manager
	managerLogin, err := authSvc.Login(ctx, dto.LoginInput{
		Email:    "manager@erp.local",
		Password: "Password123!",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Manager login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n[SUCCESS] Test Manager logged in successfully! UserID: %s\nToken: %s\n", managerLogin.User.ID, managerLogin.Token)

	// 3. Confirm Auth's tokens satisfy Manager's verifier
	pubKey := &privKey.PublicKey

	fmt.Println("\n--- Verifying Admin Token against Manager's Verifier ---")
	adminClaims, err := verifyManagerToken(adminLogin.Token, pubKey, issuer, audience)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Manager verifier rejected admin token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Admin Claims Validated:\n  user_id: %s\n  sub: %s\n  email: %s\n  token_version: %d\n  permissions (%d): %v\n  lifetime: %v\n",
		adminClaims.UserID, adminClaims.Subject, adminClaims.Email, *adminClaims.TokenVersion, len(adminClaims.Permissions), adminClaims.Permissions,
		adminClaims.ExpiresAt.Sub(adminClaims.IssuedAt.Time),
	)

	fmt.Println("\n--- Verifying Manager Token against Manager's Verifier ---")
	managerClaims, err := verifyManagerToken(managerLogin.Token, pubKey, issuer, audience)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Manager verifier rejected manager token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Manager Claims Validated:\n  user_id: %s\n  sub: %s\n  email: %s\n  token_version: %d\n  permissions (%d): %v\n  lifetime: %v\n",
		managerClaims.UserID, managerClaims.Subject, managerClaims.Email, *managerClaims.TokenVersion, len(managerClaims.Permissions), managerClaims.Permissions,
		managerClaims.ExpiresAt.Sub(managerClaims.IssuedAt.Time),
	)

	// Output token details for subsequent verification
	tokenFile := "keys/test_tokens.json"
	data, _ := json.MarshalIndent(map[string]string{
		"admin_token":     adminLogin.Token,
		"manager_token":   managerLogin.Token,
		"admin_user_id":   adminLogin.User.ID.String(),
		"manager_user_id": managerLogin.User.ID.String(),
	}, "", "  ")
	_ = os.WriteFile(tokenFile, data, 0644)
	fmt.Printf("\nSaved fresh test tokens to %s\n", tokenFile)
}
