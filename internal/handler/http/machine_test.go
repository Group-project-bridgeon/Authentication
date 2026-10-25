package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/group-project/authentication/internal/domain"
	"github.com/rs/zerolog"
)

type machineStub struct {
	calls int
	err   error
}

func (s *machineStub) Issue(context.Context, string, string) (string, error) {
	s.calls++
	return "synthetic-token", s.err
}
func (*machineStub) TTL() time.Duration { return 5 * time.Minute }
func TestMachineEndpointValidation(t *testing.T) {
	form := "grant_type=client_credentials&audience=catalog-stock-references&scope=catalog.stock-references%3Aread"
	cases := []struct {
		name, body, content, query string
		tls, basic                 bool
		err                        error
		status                     int
	}{
		{"valid", form, "application/x-www-form-urlencoded", "", true, true, nil, 200},
		{"plain HTTP", form, "application/x-www-form-urlencoded", "", false, true, nil, 400},
		{"query", form, "application/x-www-form-urlencoded", "?client_secret=synthetic-secret", true, true, nil, 400},
		{"json", `{}`, "application/json", "", true, true, nil, 400},
		{"large", strings.Repeat("x", 4097), "application/x-www-form-urlencoded", "", true, true, nil, 400},
		{"duplicate", form + "&scope=x", "application/x-www-form-urlencoded", "", true, true, nil, 400},
		{"body credential", form + "&client_secret=x", "application/x-www-form-urlencoded", "", true, true, nil, 400},
		{"missing basic", form, "application/x-www-form-urlencoded", "", true, false, nil, 401},
		{"rejected client", form, "application/x-www-form-urlencoded", "", true, true, domain.ErrMachineClient, 401},
		{"database", form, "application/x-www-form-urlencoded", "", true, true, &domain.MachineFailure{SQLState: "08006", Reason: "database_failure"}, 503},
		{"raw error", form, "application/x-www-form-urlencoded", "", true, true, errors.New("synthetic-sensitive-error"), 503},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			stub := &machineStub{err: tt.err}
			h := NewMachineHandler(stub, zerolog.New(&logs))
			r := gin.New()
			r.POST("/token", h.Token)
			req := httptest.NewRequest("POST", "/token"+tt.query, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.content)
			req.Header.Set("X-Forwarded-Proto", "https")
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.basic {
				req.SetBasicAuth("synthetic-client", "synthetic-secret")
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("status %d want %d", w.Code, tt.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
				t.Fatal("cache headers")
			}
			if tt.status == 400 && stub.calls != 0 {
				t.Fatal("invalid request reached issuer")
			}
			for _, bad := range []string{"synthetic-secret", "synthetic-token", "synthetic-sensitive-error"} {
				if strings.Contains(logs.String(), bad) {
					t.Fatal("sensitive log")
				}
			}
		})
	}
}
func TestMachineEndpointAdmissionBound(t *testing.T) {
	h := NewMachineHandler(&machineStub{}, zerolog.Nop())
	h.mu.Lock()
	h.tokens = 0
	h.last = time.Now()
	h.mu.Unlock()
	r := gin.New()
	r.POST("/token", h.Token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/token", nil))
	if w.Code != 429 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("admission not bounded")
	}
}
