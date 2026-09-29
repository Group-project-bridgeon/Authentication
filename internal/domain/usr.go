package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmailTaken         = errors.New("email already registered")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailNotVerified   = errors.New("email is not verified")
	ErrInvalidOTP         = errors.New("invalid or expired verification code")
	ErrOTPMaxAttempts     = errors.New("too many invalid attempts, please request a new verification code")
	ErrOTPCooldown        = errors.New("please wait before requesting another verification code")
	ErrAlreadyVerified    = errors.New("email is already verified")
)

type User struct {
	ID           uuid.UUID
	Email        string
	Name         string
	PasswordHash string
	CreatedAt    time.Time
	IsVerified   bool
}

type EmailVerification struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	OtpHash    string
	Attempts   int
	ExpiresAt  time.Time
	LastSentAt time.Time
	CreatedAt  time.Time
}

type PasswordReset struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	OtpHash    string
	Attempts   int
	ExpiresAt  time.Time
	LastSentAt time.Time
	CreatedAt  time.Time
}

type UserRepository interface {
	Create(ctx context.Context, u *User) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	SetVerified(ctx context.Context, id uuid.UUID) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}

type VerificationRepository interface {
	Upsert(ctx context.Context, v *EmailVerification) (*EmailVerification, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*EmailVerification, error)
	IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

type PasswordResetRepository interface {
	Upsert(ctx context.Context, p *PasswordReset) (*PasswordReset, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*PasswordReset, error)
	IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}