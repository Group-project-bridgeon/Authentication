package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmailTaken            = errors.New("email already registered")
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrInvalidInput          = errors.New("invalid input")
	ErrInvalidOTP            = errors.New("invalid OTP")
	ErrEmailNotVerified      = errors.New("email is not verified")
	ErrAlreadyVerified       = errors.New("email is already verified")
	ErrOAuthNotConfigured    = errors.New("OAuth is not configured")
	ErrInvalidOAuthState     = errors.New("invalid OAuth state")
	ErrOAuthEmailNotVerified = errors.New("OAuth email is not verified")
	ErrOTPAttemptsExceeded   = errors.New("maximum verification attempts exceeded")
	ErrOTPCooldown           = errors.New("please wait before requesting another code")
)

type User struct {
	ID                 uuid.UUID
	Email              string
	FullName           string
	IsActive           bool
	MustChangePassword bool
	TokenVersion       int32

	LastLoginAt     *time.Time
	DeactivatedAt   *time.Time
	DeactivatedBy   *uuid.UUID
	CreatedBy       *uuid.UUID
	EmailVerifiedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserRepository interface {
	Create(ctx context.Context, user *User) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	SetEmailVerified(ctx context.Context, id uuid.UUID) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID, loginAt time.Time) error
	IncrementTokenVersion(ctx context.Context, id uuid.UUID) (int32, error)
}
