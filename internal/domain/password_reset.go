package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type PasswordResetToken struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TokenHash    []byte
	AttemptCount int32
	ExpiresAt    time.Time
	UsedAt       *time.Time
	CreatedAt    time.Time
}

type PasswordResetRepository interface {
	CreateToken(
		ctx context.Context,
		token *PasswordResetToken,
	) (*PasswordResetToken, error)

	GetByHash(
		ctx context.Context,
		tokenHash []byte,
	) (*PasswordResetToken, error)

	GetLatestByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (*PasswordResetToken, error)

	GetActiveByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (*PasswordResetToken, error)

	IncrementAttempts(
		ctx context.Context,
		id uuid.UUID,
	) error

	MarkUsed(
		ctx context.Context,
		id uuid.UUID,
	) error

	DeleteByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) error
}
