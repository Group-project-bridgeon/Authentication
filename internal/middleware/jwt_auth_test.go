package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
)

func init() {
	gin.SetMode(gin.TestMode)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
	r := setupTestRouter(jwtMgr, nil)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestJWTAuth_MalformedHeader(t *testing.T) {
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", -1*time.Hour)
	r := setupTestRouter(jwtMgr, nil)

	token, _ := jwtMgr.Generate(uuid.New(), "expired@example.com")

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired token, got %d", w.Code)
	}
}

func TestJWTAuth_InvalidSignature(t *testing.T) {
	jwtMgr1 := helper.NewJWTManager("secret-key-one-at-least-32-bytes-long", 1*time.Hour)
	jwtMgr2 := helper.NewJWTManager("secret-key-two-at-least-32-bytes-long", 1*time.Hour)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
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
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
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
