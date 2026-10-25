package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
)

type machineRepoStub struct{ calls int }

func (*machineRepoStub) Create(context.Context, uuid.UUID) error           { return nil }
func (*machineRepoStub) SetEnabled(context.Context, uuid.UUID, bool) error { return nil }
func (*machineRepoStub) SetGrant(context.Context, uuid.UUID, bool) error   { return nil }
func (*machineRepoStub) Rotate(context.Context, uuid.UUID, uuid.UUID, []byte, time.Duration) (time.Time, error) {
	return time.Now(), nil
}
func (*machineRepoStub) Revoke(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *machineRepoStub) Issue(context.Context, uuid.UUID, uuid.UUID, []byte, func(time.Time) (string, error)) (string, error) {
	s.calls++
	return "", domain.ErrMachineClient
}
func TestMachineServiceBounds(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("key")
	}
	repo := &machineRepoStub{}
	for _, ttl := range []time.Duration{0, time.Millisecond, 300*time.Second + time.Nanosecond, 301 * time.Second} {
		if _, err := NewMachineService(repo, key, "erp-auth", ttl); err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
	s, err := NewMachineService(repo, key, "erp-auth", 5*time.Minute)
	if err != nil {
		t.Fatal("valid TTL rejected")
	}
	for _, age := range []time.Duration{0, -time.Second, domain.MaxCredentialAge + time.Second} {
		if _, err := s.Rotate(context.Background(), uuid.New(), age); err == nil {
			t.Fatal("invalid age accepted")
		}
	}
	for _, password := range []string{"", "bad", uuid.NewString() + ".x", uuid.Nil.String() + ".x"} {
		if _, err := s.Issue(context.Background(), uuid.NewString(), password); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if repo.calls != 0 {
		t.Fatal("malformed credential reached repository")
	}
}
