package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/service/dto"
)

const (
	OTPExpirationDuration = 10 * time.Minute
	OTPCooldownDuration   = 60 * time.Second
	MaxOTPAttempts        = 5
)

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hash, plain string) error
}

type TokenGenerator interface {
	Generate(userID uuid.UUID, email string) (string, error)
	Duration() time.Duration
}

type AuthService struct {
	users         domain.UserRepository
	verifications domain.VerificationRepository
	hasher        PasswordHasher
	tokens        TokenGenerator
	emailSender   helper.EmailSender
}

func NewAuthService(
	u domain.UserRepository,
	v domain.VerificationRepository,
	h PasswordHasher,
	t TokenGenerator,
	e helper.EmailSender,
) *AuthService {
	return &AuthService{
		users:         u,
		verifications: v,
		hasher:        h,
		tokens:        t,
		emailSender:   e,
	}
}

func normalize(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *AuthService) Register(ctx context.Context, in dto.RegisterInput) (*dto.RegisterResult, error) {
	name := strings.TrimSpace(in.Name)
	if len(name) < 2 {
		return nil, domain.ErrInvalidInput
	}

	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}

	user, err := s.users.Create(ctx, &domain.User{
		Email:        normalize(in.Email),
		Name:         name,
		PasswordHash: hash,
	})
	if err != nil {
		return nil, err
	}

	// Generate secure 6-digit OTP
	otp, err := helper.GenerateOTP()
	if err != nil {
		return nil, err
	}

	// Hash OTP before storing
	otpHash := helper.HashOTP(otp)

	_, err = s.verifications.Upsert(ctx, &domain.EmailVerification{
		UserID:    user.ID,
		OtpHash:   otpHash,
		Attempts:  0,
		ExpiresAt: time.Now().Add(OTPExpirationDuration),
	})
	if err != nil {
		return nil, err
	}

	// Send verification code via email
	_ = s.emailSender.SendOTP(ctx, user.Email, user.Name, otp)

	return &dto.RegisterResult{
		User:    user,
		Message: "registration successful, please verify your email with the code sent",
	}, nil
}

func (s *AuthService) Login(ctx context.Context, in dto.LoginInput) (*dto.AuthResult, error) {
	u, err := s.users.GetByEmail(ctx, normalize(in.Email))
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, domain.ErrInvalidCredentials // never reveal which part was wrong
	}
	if err != nil {
		return nil, err
	}
	if err := s.hasher.Compare(u.PasswordHash, in.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !u.IsVerified {
		return nil, domain.ErrEmailNotVerified
	}

	token, err := s.tokens.Generate(u.ID, u.Email)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResult{
		User:      u,
		Token:     token,
		TokenType: "Bearer",
		ExpiresIn: int64(s.tokens.Duration().Seconds()),
	}, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, in dto.VerifyEmailInput) (*dto.AuthResult, error) {
	email := normalize(in.Email)
	otp := strings.TrimSpace(in.OTP)
	if len(otp) == 0 {
		return nil, domain.ErrInvalidOTP
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidOTP
		}
		return nil, err
	}

	if user.IsVerified {
		return nil, domain.ErrAlreadyVerified
	}

	verification, err := s.verifications.GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(verification.ExpiresAt) {
		return nil, domain.ErrInvalidOTP
	}

	// Check max attempts
	if verification.Attempts >= MaxOTPAttempts {
		return nil, domain.ErrOTPMaxAttempts
	}

	// Verify constant-time OTP hash
	if !helper.CheckOTPHash(otp, verification.OtpHash) {
		attempts, _ := s.verifications.IncrementAttempts(ctx, user.ID)
		if attempts >= MaxOTPAttempts {
			return nil, domain.ErrOTPMaxAttempts
		}
		return nil, domain.ErrInvalidOTP
	}

	// Mark verified in DB and remove verification record
	if err := s.users.SetVerified(ctx, user.ID); err != nil {
		return nil, err
	}
	_ = s.verifications.DeleteByUserID(ctx, user.ID)

	user.IsVerified = true

	token, err := s.tokens.Generate(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResult{
		User:      user,
		Token:     token,
		TokenType: "Bearer",
		ExpiresIn: int64(s.tokens.Duration().Seconds()),
	}, nil
}

func (s *AuthService) ResendOTP(ctx context.Context, in dto.ResendOTPInput) error {
	email := normalize(in.Email)
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Do not leak whether user exists to prevent email harvesting
			return nil
		}
		return err
	}

	if user.IsVerified {
		return domain.ErrAlreadyVerified
	}

	// Check cooldown rate limit (60 seconds)
	if existing, err := s.verifications.GetByUserID(ctx, user.ID); err == nil && existing != nil {
		if time.Since(existing.LastSentAt) < OTPCooldownDuration {
			return domain.ErrOTPCooldown
		}
	}

	otp, err := helper.GenerateOTP()
	if err != nil {
		return err
	}

	otpHash := helper.HashOTP(otp)

	_, err = s.verifications.Upsert(ctx, &domain.EmailVerification{
		UserID:    user.ID,
		OtpHash:   otpHash,
		Attempts:  0,
		ExpiresAt: time.Now().Add(OTPExpirationDuration),
	})
	if err != nil {
		return err
	}

	_ = s.emailSender.SendOTP(ctx, user.Email, user.Name, otp)
	return nil
}

func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, normalize(email))
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}
