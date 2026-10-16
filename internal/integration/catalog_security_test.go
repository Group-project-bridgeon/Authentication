package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/helper"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Run only via ERP-Platform/scripts/test-catalog-security.ps1 against disposable
// databases. No pre-existing user is selected, reset, or granted a role.
func TestCatalogSecurityThroughKong(t *testing.T) {
	if os.Getenv("ERP_SECURITY_ISOLATED") != "1" {
		t.Skip("isolated Docker fixture not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	connect := func(env, dbName string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(os.Getenv(env))
		if err != nil || cfg.ConnConfig.Database != dbName {
			t.Fatalf("%s must target isolated %s", env, dbName)
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("cannot open isolated database")
		}
		t.Cleanup(pool.Close)
		if err = pool.Ping(ctx); err != nil {
			t.Fatal("isolated database unavailable")
		}
		return pool
	}
	authDB := connect("TEST_DATABASE_URL", "auth_security_test")
	catalogDB := connect("CATALOG_TEST_DATABASE_URL", "catalog_security_test")
	base := os.Getenv("ERP_SECURITY_GATEWAY_URL")
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatal("fixture requires loopback gateway URL")
	}
	keyData, err := os.ReadFile(os.Getenv("ERP_SECURITY_PUBLIC_KEY"))
	if err != nil {
		t.Fatal("fixture public key unavailable")
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		t.Fatal("fixture public key invalid")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(method, path, token string, body any, want int) []byte {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal("build request failed")
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("HTTP fixture request failed")
		}
		defer res.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			t.Fatal("read fixture response failed")
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: HTTP %d, want %d (response intentionally redacted)", method, path, res.StatusCode, want)
		}
		t.Logf("%s %s: HTTP %d", method, path, res.StatusCode)
		return payload
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := authDB.Exec(ctx, sql, args...); err != nil {
			t.Fatal("fixture SQL failed (details redacted)")
		}
	}
	fixture := func(actions []string, scope string) (string, *helper.Claims) {
		id, role := uuid.New(), uuid.New()
		email := "catalog-security-" + id.String() + "@example.invalid"
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		password := hex.EncodeToString(secret)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO identity_users (id,email,full_name,email_verified_at) VALUES ($1,$2,'Isolated Catalog test',now())`, id, email)
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, stmt := range []string{`DELETE FROM identity_user_roles WHERE user_id=$1`, `DELETE FROM identity_credentials WHERE user_id=$1`, `DELETE FROM identity_users WHERE id=$1`} {
				if _, err := authDB.Exec(cleanupCtx, stmt, id); err != nil {
					t.Error("fixture user cleanup failed")
				}
			}
			if _, err := authDB.Exec(cleanupCtx, `DELETE FROM identity_role_permissions WHERE role_id=$1`, role); err != nil {
				t.Error("fixture role cleanup failed")
			}
			if _, err := authDB.Exec(cleanupCtx, `DELETE FROM identity_roles WHERE id=$1`, role); err != nil {
				t.Error("fixture role cleanup failed")
			}
		})
		exec(`INSERT INTO identity_credentials (user_id,password_hash) VALUES ($1,$2)`, id, string(hash))
		if len(actions) > 0 {
			exec(`INSERT INTO identity_roles (id,name,description) VALUES ($1,$2,'Disposable test only')`, role, "catalog-test-"+role.String())
			for _, action := range actions {
				tag, err := authDB.Exec(ctx, `INSERT INTO identity_role_permissions (role_id,permission_id) SELECT $1,id FROM identity_permissions WHERE resource='catalog.brands' AND action=$2`, role, action)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("Catalog permission migration missing")
				}
			}
			var scopeID any
			if scope == "WAREHOUSE" {
				scopeID = uuid.New()
			}
			exec(`INSERT INTO identity_user_roles (user_id,role_id,scope_type,scope_id) VALUES ($1,$2,$3,$4)`, id, role, scope, scopeID)
		}
		payload := request("POST", "/api/v1/auth/login", "", map[string]string{"email": email, "password": password}, 200)
		var login struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(payload, &login); err != nil || login.TokenType != "Bearer" || login.ExpiresIn < 1 || login.ExpiresIn > 900 {
			t.Fatal("invalid login response contract")
		}
		claims := &helper.Claims{}
		parsed, err := jwt.ParseWithClaims(login.AccessToken, claims, func(token *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("erp-auth"), jwt.WithAudience("erp-api"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		if err != nil || !parsed.Valid || claims.UserID != id || claims.TokenVersion != 0 {
			t.Fatal("runtime token signature/claim verification failed")
		}
		if int64(claims.ExpiresAt.Sub(claims.IssuedAt.Time).Seconds()) != login.ExpiresIn {
			t.Fatal("runtime token duration mismatch")
		}
		me := request("GET", "/api/v1/auth/me", login.AccessToken, nil, 200)
		var user struct {
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(me, &user); err != nil || user.ID != id {
			t.Fatal("authenticated /me identity mismatch")
		}
		return login.AccessToken, claims
	}
	allowed, grants := fixture([]string{"read", "create", "update"}, "GLOBAL")
	if len(grants.Permissions) != 3 {
		t.Fatal("GLOBAL permissions missing")
	}
	reader, _ := fixture([]string{"read"}, "GLOBAL")
	empty, emptyClaims := fixture(nil, "GLOBAL")
	warehouse, scoped := fixture([]string{"read", "create", "update"}, "WAREHOUSE")
	if len(emptyClaims.Permissions) != 0 || len(scoped.Permissions) != 0 {
		t.Fatal("non-global grants leaked into JWT")
	}
	const path = "/api/v1/catalog/brands"
	code := "SEC-" + uuid.NewString()
	body := map[string]string{"name": "Security fixture", "code": code}
	request("GET", "/api/v1/auth/me", "", nil, 401)
	request("POST", path, "", body, 401)
	request("POST", path, reader, body, 403)
	request("POST", path, empty, body, 403)
	request("POST", path, warehouse, body, 403)
	var count int
	if err := catalogDB.QueryRow(ctx, `SELECT count(*) FROM catalog_brands WHERE code=$1`, code).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied create changed database")
	}
	payload := request("POST", path, allowed, body, 201)
	var brand struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(payload, &brand); err != nil || brand.ID == uuid.Nil {
		t.Fatal("brand create contract failed")
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := catalogDB.Exec(cleanupCtx, `DELETE FROM catalog_brands WHERE id=$1`, brand.ID); err != nil {
			t.Error("fixture Catalog cleanup failed")
		}
	})
	item := path + "/" + brand.ID.String()
	request("GET", item, reader, nil, 200)
	request("GET", path, reader, nil, 200)
	request("GET", item, warehouse, nil, 403)
	request("GET", item, empty, nil, 403)
	update := map[string]string{"name": "Updated security fixture", "code": code}
	request("PUT", item, "", update, 401)
	request("PUT", item, reader, update, 403)
	request("PATCH", item+"/status", reader, map[string]bool{"is_active": false}, 403)
	var name string
	var active bool
	if err := catalogDB.QueryRow(ctx, `SELECT name,is_active FROM catalog_brands WHERE id=$1`, brand.ID).Scan(&name, &active); err != nil || name != "Security fixture" || !active {
		t.Fatal("denied update changed database")
	}
	request("PUT", item, allowed, update, 200)
	request("PATCH", item+"/status", allowed, map[string]bool{"is_active": false}, 200)
	if err := catalogDB.QueryRow(ctx, `SELECT name,is_active FROM catalog_brands WHERE id=$1`, brand.ID).Scan(&name, &active); err != nil || name != "Updated security fixture" || active {
		t.Fatal("authorized update not persisted")
	}
}
