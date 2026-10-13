package router_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/group-project/authentication/internal/router"
)

// fakeDB is a minimal stub that satisfies router.DatabaseHealthChecker.
type fakeDB struct {
	pingErr error
}

func (f *fakeDB) Ping(_ context.Context) error {
	return f.pingErr
}

// buildRouter creates a minimal *router.Route for probe-only tests.
// authHandler, jwtManager, and userProvider are nil because the test
// endpoints under test (/health, /ready) do not touch them.
func buildRouter(db router.DatabaseHealthChecker) *router.Route {
	return router.NewRouter(nil, nil, nil, db)
}

// ---- Tests ------------------------------------------------------------------

// TestHealth_ReturnsOK verifies that /health always responds 200,
// regardless of the database state.
func TestHealth_ReturnsOK(t *testing.T) {
	// Pass an unhealthy DB to prove /health does NOT depend on it.
	r := buildRouter(&fakeDB{pingErr: errors.New("db is down")}).Router()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/health: expected 200, got %d", w.Code)
	}
}

// TestReady_DatabaseHealthy verifies that /ready returns 200 with
// {"status":"ready"} when the DB ping succeeds.
func TestReady_DatabaseHealthy(t *testing.T) {
	r := buildRouter(&fakeDB{pingErr: nil}).Router()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/ready (healthy): expected 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["status"] != "ready" {
		t.Fatalf("expected status=ready, got %q", body["status"])
	}
}

// TestReady_DatabaseUnavailable verifies that /ready returns 503 with
// {"status":"not ready"} when the DB ping fails, and does NOT expose the
// raw database error text in the response body.
func TestReady_DatabaseUnavailable(t *testing.T) {
	dbErr := errors.New("dial tcp: connection refused — SECRET_DSN_INFO")
	r := buildRouter(&fakeDB{pingErr: dbErr}).Router()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready (unhealthy): expected 503, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["status"] != "not ready" {
		t.Fatalf("expected status=not ready, got %q", body["status"])
	}

	// Response body must NOT expose the raw database error string.
	rawBody := w.Body.String()
	if contains(rawBody, dbErr.Error()) {
		t.Fatalf("response must not expose raw DB error; got body: %s", rawBody)
	}
}

// TestReady_NilChecker verifies that /ready returns 503 and does NOT
// panic when the DatabaseHealthChecker is nil (fail-closed behaviour).
func TestReady_NilChecker(t *testing.T) {
	// Pass nil directly to prove fail-closed.
	r := router.NewRouter(nil, nil, nil, nil).Router()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()

	// Should not panic.
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready (nil checker): expected 503, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["status"] != "not ready" {
		t.Fatalf("expected status=not ready, got %q", body["status"])
	}
}

// contains is a simple string-contains helper to avoid importing strings in
// test code unnecessarily.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
