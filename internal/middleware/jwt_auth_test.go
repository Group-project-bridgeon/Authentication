package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/helper"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRouter(jwtMgr *helper.JWTManager) *gin.Engine {
	r := gin.New()
	r.Use(JWTAuth(jwtMgr))
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
	r := setupTestRouter(jwtMgr)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestJWTAuth_MalformedHeader(t *testing.T) {
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
	r := setupTestRouter(jwtMgr)

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
	r := setupTestRouter(jwtMgr)

	token, _ := jwtMgr.Generate(uuid.New(), "expired@example.com")

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired token, got %d", w.Code)
	}
}

func TestJWTAuth_ValidToken(t *testing.T) {
	jwtMgr := helper.NewJWTManager("test-secret-at-least-32-bytes-long", 1*time.Hour)
	r := setupTestRouter(jwtMgr)

	userID := uuid.New()
	email := "valid@example.com"
	token, _ := jwtMgr.Generate(userID, email)

	req, _ := http.NewRequest(http.MethodGet, "/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
}
