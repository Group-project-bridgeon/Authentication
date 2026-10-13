package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Credential struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	PasswordHash      *string
	PasswordChangedAt *time.Time
	FailedLoginCount  int32
	LockedUntil       *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type CredentialRepository interface {
	Create(ctx context.Context, credential *Credential) (*Credential, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*Credential, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
}
