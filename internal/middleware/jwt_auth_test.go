package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestJWTManager(t *testing.T) (*helper.JWTManager, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := helper.NewJWTManager(key, "erp-auth", "erp-api", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	return manager, key
}

type mockTokenUserProvider struct {
	users map[uuid.UUID]*domain.User
	err   error
}

func (m *mockTokenUserProvider) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	u, ok := m.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func setupTestRouter(jwtMgr *helper.JWTManager, up TokenUserProvider) *gin.Engine {
	r := gin.New()
	r.Use(JWTAuth(jwtMgr, up))
	r.GET("/test-protected", func(c *gin.Context) {
		uid, _ := GetUserID(c)
		email, _ := GetUserEmail(c)
		c.JSON(http.StatusOK, gin.H{
			"user_id": uid.String(),
			"email":   email,
		})
	})
	return r
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	r := setupTestRouter(jwtMgr, nil)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestJWTAuth_MalformedHeader(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	r := setupTestRouter(jwtMgr, nil)

	testCases := []string{
		"Basic 12345",
		"Bearer",
		"Token abcde",
	}

	for _, tc := range testCases {
		req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
		req.Header.Set("Authorization", tc)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: expected 401 Unauthorized, got %d", tc, w.Code)
		}
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	jwtMgr, key := newTestJWTManager(t)
	r := setupTestRouter(jwtMgr, nil)

	past := time.Now().UTC().Add(-20 * time.Minute)
	userID := uuid.New()
	claims := helper.Claims{
		UserID:       userID,
		Email:        "expired@example.com",
		TokenVersion: 0,
		Permissions:  []string{},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "erp-auth",
			Audience:  jwt.ClaimStrings{"erp-api"},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(past),
			NotBefore: jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(10 * time.Minute)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("unexpected token generation error: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired token, got %d", w.Code)
	}
}

func TestJWTAuth_InvalidSignature(t *testing.T) {
	jwtMgr1, _ := newTestJWTManager(t)
	jwtMgr2, _ := newTestJWTManager(t)
	r := setupTestRouter(jwtMgr2, nil)

	token, _ := jwtMgr1.Generate(uuid.New(), "test@example.com")

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for invalid signature, got %d", w.Code)
	}
}

func TestJWTAuth_ValidToken_SameTokenVersion(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	userID := uuid.New()
	email := "valid@example.com"

	provider := &mockTokenUserProvider{
		users: map[uuid.UUID]*domain.User{
			userID: {
				ID:           userID,
				Email:        email,
				IsActive:     true,
				TokenVersion: 2,
			},
		},
	}
	r := setupTestRouter(jwtMgr, provider)

	token, err := jwtMgr.GenerateVersioned(userID, email, 2)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJWTAuth_TokenVersionMismatch(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	userID := uuid.New()
	email := "valid@example.com"

	provider := &mockTokenUserProvider{
		users: map[uuid.UUID]*domain.User{
			userID: {
				ID:           userID,
				Email:        email,
				IsActive:     true,
				TokenVersion: 3, // user has bumped version to 3
			},
		},
	}
	r := setupTestRouter(jwtMgr, provider)

	// Token was generated with version 2
	token, err := jwtMgr.GenerateVersioned(userID, email, 2)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJWTAuth_InactiveUser(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	userID := uuid.New()
	email := "inactive@example.com"

	provider := &mockTokenUserProvider{
		users: map[uuid.UUID]*domain.User{
			userID: {
				ID:           userID,
				Email:        email,
				IsActive:     false, // deactivated account
				TokenVersion: 1,
			},
		},
	}
	r := setupTestRouter(jwtMgr, provider)

	token, _ := jwtMgr.GenerateVersioned(userID, email, 1)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for inactive user, got %d", w.Code)
	}
}

func TestJWTAuth_MissingUser(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	userID := uuid.New()
	email := "missing@example.com"

	provider := &mockTokenUserProvider{
		users: map[uuid.UUID]*domain.User{}, // empty user store
	}
	r := setupTestRouter(jwtMgr, provider)

	token, _ := jwtMgr.GenerateVersioned(userID, email, 1)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing user, got %d", w.Code)
	}
}

func TestJWTAuth_ValidTokenWithoutUserProvider_FailsClosed(t *testing.T) {
	jwtMgr, _ := newTestJWTManager(t)
	userID := uuid.New()
	token, err := jwtMgr.GenerateVersioned(userID, "failclosed@example.com", 0)
	if err != nil {
		t.Fatalf("unexpected token generation error: %v", err)
	}

	r := setupTestRouter(jwtMgr, nil)
	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user provider is unavailable, got %d: %s", w.Code, w.Body.String())
	}
}
