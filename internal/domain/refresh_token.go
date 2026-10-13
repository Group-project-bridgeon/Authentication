package domain

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	FamilyID        uuid.UUID
	TokenHash       []byte
	ReplacedByID    *uuid.UUID
	ReplacedAt      *time.Time
	UserAgent       *string
	IPAddress       *netip.Addr
	ExpiresAt       time.Time
	FamilyExpiresAt time.Time
	RevokedAt       *time.Time
	RevokedReason   *string
	LastUsedAt      *time.Time
	CreatedAt       time.Time
}

type RefreshTokenRepository interface {
	Create(
		ctx context.Context,
		token *RefreshToken,
	) (*RefreshToken, error)

	GetByHash(
		ctx context.Context,
		tokenHash []byte,
	) (*RefreshToken, error)

	GetByID(
		ctx context.Context,
		id uuid.UUID,
	) (*RefreshToken, error)

	GetFamily(
		ctx context.Context,
		familyID uuid.UUID,
	) ([]*RefreshToken, error)

	Rotate(
		ctx context.Context,
		id uuid.UUID,
		replacedByID uuid.UUID,
	) error

	Revoke(
		ctx context.Context,
		id uuid.UUID,
		reason string,
	) error

	RevokeFamily(
		ctx context.Context,
		familyID uuid.UUID,
		reason string,
	) error

	UpdateLastUsed(
		ctx context.Context,
		id uuid.UUID,
	) error

	DeleteExpired(
		ctx context.Context,
	) error
}
