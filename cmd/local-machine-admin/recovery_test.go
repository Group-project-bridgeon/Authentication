package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/service"
)

type faultRepository struct {
	domain.MachineRepository
	dir, failAt                 string
	creates, rotations, enables int
	t                           *testing.T
}

func (r *faultRepository) intent(id uuid.UUID, phase string) {
	b, e := os.ReadFile(filepath.Join(r.dir, "machine-journal.jsonl"))
	if e != nil || !strings.Contains(string(b), id.String()) || !strings.Contains(string(b), phase) {
		r.t.Fatal("database call preceded durable intent")
	}
}
func (r *faultRepository) Create(_ context.Context, id uuid.UUID) error {
	r.creates++
	r.intent(id, "create-intent")
	if r.failAt == "create" {
		return domain.ErrMachineOutcomeUnknown
	}
	return nil
}
func (r *faultRepository) SetGrant(context.Context, uuid.UUID, bool) error { return nil }
func (r *faultRepository) Rotate(_ context.Context, _ uuid.UUID, cid uuid.UUID, _ []byte, _ time.Duration) (time.Time, error) {
	r.rotations++
	r.intent(cid, "rotation-intent")
	return time.Time{}, domain.ErrMachineOutcomeUnknown
}
func (r *faultRepository) SetEnabled(context.Context, uuid.UUID, bool) error { r.enables++; return nil }
func TestUnknownProvisioningHasDurableIntentAndNoRetry(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal("key")
	}
	for _, phase := range []string{"create", "rotate"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			repo := &faultRepository{dir: dir, failAt: phase, t: t}
			factory := func(remember func(uuid.UUID, uuid.UUID, string) error) (lifecycle, error) {
				return service.NewMachineService(intentRepository{repo, remember}, key, "fixture", 5*time.Minute)
			}
			r, e := provision(context.Background(), factory, dir)
			if !errors.Is(e, domain.ErrMachineOutcomeUnknown) || r.Machine == uuid.Nil {
				t.Fatal("unknown outcome lost")
			}
			if phase == "rotate" && r.Credential == uuid.Nil {
				t.Fatal("credential reconciliation ID lost")
			}
			if _, e = provision(context.Background(), factory, dir); e == nil || repo.creates != 1 || repo.enables != 0 {
				t.Fatal("unsafe automatic provisioning retry")
			}
			b, e := os.ReadFile(filepath.Join(dir, "inventory-credential.json"))
			if e != nil || len(b) != 0 {
				t.Fatal("unknown credential was delivered")
			}
			b, e = os.ReadFile(filepath.Join(dir, "machine-journal.jsonl"))
			if e != nil {
				t.Fatal("journal")
			}
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				var entry receipt
				if json.Unmarshal([]byte(line), &entry) != nil {
					t.Fatal("invalid journal record")
				}
			}
		})
	}
}
func TestLocalHostGuard(t *testing.T) {
	for _, host := range []string{"", "production.example.com", "postgres.example.com"} {
		if localHost(host) {
			t.Fatal("non-local host accepted")
		}
	}
}
