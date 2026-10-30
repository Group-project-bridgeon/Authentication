package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
)

type MachineService struct {
	repo   domain.MachineRepository
	key    *rsa.PrivateKey
	issuer string
	ttl    time.Duration
}

func NewMachineService(repo domain.MachineRepository, key *rsa.PrivateKey, issuer string, ttl time.Duration) (*MachineService, error) {
	if repo == nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil || issuer == "" || strings.TrimSpace(issuer) != issuer || ttl < time.Second || ttl > domain.MaxMachineTTL || ttl%time.Second != 0 {
		return nil, domain.ErrMachineInput
	}
	return &MachineService{repo, key, issuer, ttl}, nil
}
func (s *MachineService) TTL() time.Duration { return s.ttl }
func (s *MachineService) Create(ctx context.Context) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, domain.ErrMachineUnavailable
	}
	return id, s.repo.Create(ctx, id)
}
func (s *MachineService) SetEnabled(ctx context.Context, id uuid.UUID, value bool) error {
	return s.repo.SetEnabled(ctx, id, value)
}
func (s *MachineService) SetGrant(ctx context.Context, id uuid.UUID, value bool) error {
	return s.repo.SetGrant(ctx, id, value)
}

func (s *MachineService) SetAuthorityGrant(ctx context.Context, id uuid.UUID, a domain.MachineAuthority, value bool) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if scoped, ok := s.repo.(domain.ScopedMachineGrantRepository); ok {
		return scoped.SetAuthorityGrant(ctx, id, a, value)
	}
	return domain.ErrMachineUnavailable
}
func (s *MachineService) Revoke(ctx context.Context, id, credential uuid.UUID) error {
	return s.repo.Revoke(ctx, id, credential)
}
func (s *MachineService) Rotate(ctx context.Context, id uuid.UUID, age time.Duration) (domain.MachineCredential, error) {
	if id == uuid.Nil || age < time.Second || age > domain.MaxCredentialAge {
		return domain.MachineCredential{}, domain.ErrMachineInput
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return domain.MachineCredential{}, domain.ErrMachineUnavailable
	}
	cid, err := uuid.NewV7()
	if err != nil {
		return domain.MachineCredential{}, domain.ErrMachineUnavailable
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256(secret)
	expires, err := s.repo.Rotate(ctx, id, cid, hash[:], age)
	if err != nil {
		return domain.MachineCredential{ID: cid}, err
	}
	return domain.MachineCredential{ID: cid, Secret: cid.String() + "." + encoded, ExpiresAt: expires}, nil
}
func (s *MachineService) Issue(ctx context.Context, client, password string) (string, error) {
	return s.IssueFor(ctx, client, password, domain.CatalogAuthority())
}
func (s *MachineService) IssueFor(ctx context.Context, client, password string, authority domain.MachineAuthority) (string, error) {
	if err := authority.Validate(); err != nil {
		return "", err
	}
	id, err := uuid.Parse(client)
	if err != nil || id == uuid.Nil || id.String() != client {
		return "", domain.ErrMachineClient
	}
	parts := strings.Split(password, ".")
	if len(parts) != 2 {
		return "", domain.ErrMachineClient
	}
	cid, err := uuid.Parse(parts[0])
	if err != nil || cid == uuid.Nil || cid.String() != parts[0] {
		return "", domain.ErrMachineClient
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		return "", domain.ErrMachineClient
	}
	hash := sha256.Sum256(secret)
	sign := func(now time.Time) (string, error) {
		jti, err := uuid.NewV7()
		if err != nil {
			return "", domain.ErrMachineUnavailable
		}
		now = now.UTC().Truncate(time.Second)
		claims := jwt.MapClaims{"iss": s.issuer, "aud": []string{authority.Audience}, "sub": "machine:" + id.String(), "client_id": id.String(), "token_kind": "machine", "permissions": authority.Permissions, "jti": jti.String(), "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(s.ttl).Unix()}
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(s.key)
		if err != nil {
			return "", domain.ErrMachineUnavailable
		}
		return token, nil
	}
	if scoped, ok := s.repo.(domain.ScopedMachineRepository); ok {
		return scoped.IssueFor(ctx, id, cid, hash[:], authority, sign)
	}
	if authority.Audience == domain.MachineAudience {
		return s.repo.Issue(ctx, id, cid, hash[:], sign)
	}
	return "", domain.ErrMachineUnavailable
}
