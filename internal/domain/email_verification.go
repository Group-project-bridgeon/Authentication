package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type EmailVerificationToken struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TokenHash    []byte
	AttemptCount int32
	ExpiresAt    time.Time
	VerifiedAt   *time.Time
	CreatedAt    time.Time
}

type EmailVerificationRepository interface {
	CreateToken(
		ctx context.Context,
		token *EmailVerificationToken,
	) (*EmailVerificationToken, error)

	GetByHash(
		ctx context.Context,
		tokenHash []byte,
	) (*EmailVerificationToken, error)

	GetLatestByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (*EmailVerificationToken, error)

	GetActiveByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (*EmailVerificationToken, error)

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
