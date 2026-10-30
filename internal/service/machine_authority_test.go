package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"testing"
	"time"
)

type scopedMachineStub struct {
	machineRepoStub
	authority domain.MachineAuthority
}

func (r *scopedMachineStub) IssueFor(_ context.Context, _, _ uuid.UUID, _ []byte, a domain.MachineAuthority, sign func(time.Time) (string, error)) (string, error) {
	r.authority = a
	return sign(time.Now())
}
func TestMachineServiceRequestedAuthorityOnly(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	repo := &scopedMachineStub{}
	s, err := NewMachineService(repo, key, "erp-auth", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	password := uuid.NewString() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	authority, err := domain.ParseMachineAuthority(domain.ReservationAudience, "inventory.reservations:read")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.IssueFor(context.Background(), id, password, authority)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithAudience(domain.ReservationAudience), jwt.WithIssuer("erp-auth"), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal("issued contract")
	}
	c := parsed.Claims.(jwt.MapClaims)
	p := c["permissions"].([]any)
	if c["sub"] != "machine:"+id || c["token_kind"] != "machine" || len(p) != 1 || p[0] != "inventory.reservations:read" || c["user_id"] != nil {
		t.Fatal("unexpected machine authority")
	}
	if c["exp"].(float64)-c["iat"].(float64) != 300 {
		t.Fatal("machine issued lifetime changed")
	}
}
