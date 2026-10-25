package config

import (
	"testing"
	"time"
)

func TestMachineConfigurationLimits(t *testing.T) {
	t.Setenv("DATABASE_URL", "synthetic-unused")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "synthetic-unused")
	t.Setenv("JWT_ISSUER", "erp-auth")
	t.Setenv("JWT_AUDIENCE", "erp-api")
	t.Setenv("JWT_EXPIRY", "15m")
	t.Setenv("TLS_CERT_PATH", "")
	t.Setenv("TLS_KEY_PATH", "")
	for _, value := range []string{"0s", "301s", "300.001s", "-1s", "invalid"} {
		t.Setenv("MACHINE_JWT_EXPIRY", value)
		if _, err := Load(); err == nil {
			t.Fatal("invalid machine TTL accepted")
		}
	}
	t.Setenv("MACHINE_JWT_EXPIRY", "")
	cfg, err := Load()
	if err != nil || cfg.MachineJWTExpiry != 5*time.Minute {
		t.Fatal("default machine TTL")
	}
	t.Setenv("TLS_CERT_PATH", "synthetic-unused")
	if _, err := Load(); err == nil {
		t.Fatal("partial TLS config accepted")
	}
}
