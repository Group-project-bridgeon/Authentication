package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLocalMachineProvisioning(t *testing.T) {
	raw := os.Getenv("LOCAL_PROVISION_AUTH_URL")
	if raw == "" {
		t.Skip("requires owned provisioning fixture")
	}
	c, e := pgxpool.ParseConfig(raw)
	if e != nil || c.ConnConfig.Host != "127.0.0.1" || c.ConnConfig.Database != "local_provision_auth_test" || c.ConnConfig.User != "local_provision_test" {
		t.Fatal("unsafe fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal("fixture pool")
	}
	defer p.Close()
	var marker string
	if p.QueryRow(ctx, "SELECT current_setting('local.provision_fixture')").Scan(&marker) != nil || marker != os.Getenv("LOCAL_PROVISION_RUN_ID") || marker == "" {
		t.Fatal("fixture marker")
	}
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal("key")
	}
	s, e := service.NewMachineService(postgres.NewMachineRepository(p), k, "erp-auth", 5*time.Minute)
	if e != nil {
		t.Fatal("service")
	}
	dir := t.TempDir()
	factory := func(remember func(uuid.UUID, uuid.UUID, string) error) (lifecycle, error) {
		return service.NewMachineService(intentRepository{postgres.NewMachineRepository(p), remember}, k, "erp-auth", 5*time.Minute)
	}
	r, e := provision(ctx, factory, dir)
	if e != nil || r.Phase != "enabled" {
		t.Fatal("provision failed")
	}
	var credential struct {
		ID     string `json:"credential_id"`
		Secret string `json:"secret"`
	}
	b, e := os.ReadFile(filepath.Join(dir, "inventory-credential.json"))
	if e != nil || json.Unmarshal(b, &credential) != nil {
		t.Fatal("delivery")
	}
	if _, e = s.Issue(ctx, r.Machine.String(), credential.ID+"."+credential.Secret); e != nil {
		t.Fatal("delivered credential cannot issue")
	}
	if _, e = provision(ctx, factory, dir); e == nil {
		t.Fatal("duplicate provisioning allowed")
	}
	var identities, grants, credentials int
	if p.QueryRow(ctx, "SELECT (SELECT count(*) FROM machine_identities),(SELECT count(*) FROM machine_grants),(SELECT count(*) FROM machine_credentials WHERE octet_length(secret_hash)=32)").Scan(&identities, &grants, &credentials) != nil || identities != 1 || grants != 1 || credentials != 1 {
		t.Fatal("unexpected provisioning scope")
	}
	if time.Until(r.Expiry) > 30*24*time.Hour {
		t.Fatal("expiry")
	}
	t.Log("real service provisioning, protected delivery, issuance and duplicate-run rejection passed; secret withheld")
}
