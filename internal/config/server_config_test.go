package config

import (
	"testing"
	"time"
)

func TestLoadJWTConfiguration(t *testing.T) {
	setValid := func(t *testing.T) {
		t.Helper()
		t.Setenv("DATABASE_URL", "postgres://test-only")
		t.Setenv("JWT_PRIVATE_KEY_PATH", "test-key.pem")
		t.Setenv("JWT_ISSUER", "erp-auth")
		t.Setenv("JWT_AUDIENCE", "erp-api")
		t.Setenv("JWT_EXPIRY", "")
	}

	t.Run("defaults to fifteen minutes", func(t *testing.T) {
		setValid(t)
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.JWTExpiry != 15*time.Minute {
			t.Fatalf("unexpected expiry: %v", cfg.JWTExpiry)
		}
	})

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"missing key path", "JWT_PRIVATE_KEY_PATH", ""},
		{"missing issuer", "JWT_ISSUER", ""},
		{"missing audience", "JWT_AUDIENCE", ""},
		{"whitespace issuer", "JWT_ISSUER", " erp-auth"},
		{"whitespace audience", "JWT_AUDIENCE", "erp-api "},
		{"invalid expiry", "JWT_EXPIRY", "wrong"},
		{"zero expiry", "JWT_EXPIRY", "0s"},
		{"negative expiry", "JWT_EXPIRY", "-1m"},
		{"too short", "JWT_EXPIRY", "500ms"},
		{"too long", "JWT_EXPIRY", "16m"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setValid(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
