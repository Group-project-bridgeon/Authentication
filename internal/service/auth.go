package service

import (
	"context"
	"errors"
	"log/slog"
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
	dummyBcryptHash       = "$2a$12$e80y9mU63Zf0lO8eP941se/qI8gU7YyF2aB7h3S5cW5qP0qJ2z2qy"
)

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hash, plain string) error
}

type TokenGenerator interface {
	Generate(userID uuid.UUID, email string) (string, error)
	Duration() time.Duration
}

type versionedTokenGenerator interface {
	GenerateVersioned(userID uuid.UUID, email string, version int32) (string, error)
}

type AuthService struct {
	users            domain.UserRepository
	credentials      domain.CredentialRepository
	externalIdentity domain.ExternalIdentityRepository
	verifications    domain.EmailVerificationRepository
	passwordResets   domain.PasswordResetRepository
	txManager        domain.TransactionManager
	hasher           PasswordHasher
	tokens           TokenGenerator
	emailSender      helper.EmailSender
	oauth            helper.OAuthProvider
}

func NewAuthService(
	u domain.UserRepository,
	c domain.CredentialRepository,
	ei domain.ExternalIdentityRepository,
	v domain.EmailVerificationRepository,
	pr domain.PasswordResetRepository,
	tm domain.TransactionManager,
	h PasswordHasher,
	t TokenGenerator,
	e helper.EmailSender,
	o helper.OAuthProvider,
) *AuthService {
	return &AuthService{
		users:            u,
		credentials:      c,
		externalIdentity: ei,
		verifications:    v,
		passwordResets:   pr,
		txManager:        tm,
		hasher:           h,
		tokens:           t,
		emailSender:      e,
		oauth:            o,
	}
}

func normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *AuthService) generateToken(u *domain.User) (string, error) {
	if t, ok := s.tokens.(versionedTokenGenerator); ok {
		return t.GenerateVersioned(u.ID, u.Email, u.TokenVersion)
	}
	return s.tokens.Generate(u.ID, u.Email)
}

func (s *AuthService) Register(
	ctx context.Context,
	in dto.RegisterInput,
) (*dto.RegisterResult, error) {
	name := strings.TrimSpace(in.Name)
	email := normalize(in.Email)

	if len(name) < 2 || email == "" || len(in.Password) < 8 {
		return nil, domain.ErrInvalidInput
	}

	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}

	otp, err := helper.GenerateOTP()
	if err != nil {
		return nil, err
	}

	otpHash := helper.HashOTP(otp)

	var user *domain.User

	txFn := func(uow domain.AuthUnitOfWork) error {
		var err error
		user, err = uow.Users().Create(ctx, &domain.User{
			Email:    email,
			FullName: name,
		})
		if err != nil {
			return err
		}

		_, err = uow.Credentials().Create(ctx, &domain.Credential{
			UserID:       user.ID,
			PasswordHash: &hash,
		})
		if err != nil {
			return err
		}

		_, err = uow.Verifications().CreateToken(ctx, &domain.EmailVerificationToken{
			UserID:    user.ID,
			TokenHash: []byte(otpHash),
			ExpiresAt: time.Now().Add(OTPExpirationDuration),
		})
		return err
	}

	if s.txManager != nil {
		if err := s.txManager.WithinTransaction(ctx, txFn); err != nil {
			return nil, err
		}
	} else {
		var err error
		user, err = s.users.Create(ctx, &domain.User{
			Email:    email,
			FullName: name,
		})
		if err != nil {
			return nil, err
		}

		_, err = s.credentials.Create(ctx, &domain.Credential{
			UserID:       user.ID,
			PasswordHash: &hash,
		})
		if err != nil {
			return nil, err
		}

		_, err = s.verifications.CreateToken(ctx, &domain.EmailVerificationToken{
			UserID:    user.ID,
			TokenHash: []byte(otpHash),
			ExpiresAt: time.Now().Add(OTPExpirationDuration),
		})
		if err != nil {
			return nil, err
		}
	}

	if err := s.emailSender.SendOTP(
		ctx,
		user.Email,
		user.FullName,
		otp,
	); err != nil {
		slog.Error("failed to dispatch verification email", "email", user.Email, "err", err)
	}

	return &dto.RegisterResult{
		User:    user,
		Message: "registration successful, please verify your email with the code sent",
	}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	in dto.LoginInput,
) (*dto.AuthResult, error) {
	user, err := s.users.GetByEmail(ctx, normalize(in.Email))
	if errors.Is(err, domain.ErrUserNotFound) {
		// Mitigate user enumeration timing attack
		_ = s.hasher.Compare(dummyBcryptHash, in.Password)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	credential, err := s.credentials.GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if credential.PasswordHash == nil {
		return nil, domain.ErrInvalidCredentials
	}

	if err := s.hasher.Compare(*credential.PasswordHash, in.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, domain.ErrInvalidCredentials
	}

	if user.EmailVerifiedAt == nil {
		return nil, domain.ErrEmailNotVerified
	}

	now := time.Now()
	if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now

	token, err := s.generateToken(user)
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

func (s *AuthService) VerifyEmail(
	ctx context.Context,
	in dto.VerifyEmailInput,
) error {
	email := normalize(in.Email)
	if email == "" || in.OTP == "" {
		return domain.ErrInvalidInput
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	if user.EmailVerifiedAt != nil {
		return domain.ErrAlreadyVerified
	}

	token, err := s.verifications.GetActiveByUserID(ctx, user.ID)
	if err != nil {
		return domain.ErrInvalidOTP
	}

	if token.AttemptCount >= MaxOTPAttempts {
		_ = s.verifications.DeleteByUserID(ctx, user.ID)
		return domain.ErrOTPAttemptsExceeded
	}

	if !helper.CheckOTPHash(in.OTP, string(token.TokenHash)) {
		token.AttemptCount++
		_ = s.verifications.IncrementAttempts(ctx, token.ID)
		if token.AttemptCount >= MaxOTPAttempts {
			_ = s.verifications.DeleteByUserID(ctx, user.ID)
			return domain.ErrOTPAttemptsExceeded
		}
		return domain.ErrInvalidOTP
	}

	txFn := func(uow domain.AuthUnitOfWork) error {
		if err := uow.Verifications().MarkUsed(ctx, token.ID); err != nil {
			return err
		}
		return uow.Users().SetEmailVerified(ctx, user.ID)
	}

	if s.txManager != nil {
		return s.txManager.WithinTransaction(ctx, txFn)
	}

	if err := s.verifications.MarkUsed(ctx, token.ID); err != nil {
		return err
	}

	return s.users.SetEmailVerified(ctx, user.ID)
}

func (s *AuthService) ResendOTP(
	ctx context.Context,
	in dto.ResendOTPInput,
) error {
	email := normalize(in.Email)
	if email == "" {
		return domain.ErrInvalidInput
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return err
	}

	if user.EmailVerifiedAt != nil {
		return nil
	}

	latest, err := s.verifications.GetLatestByUserID(ctx, user.ID)
	if err == nil && latest != nil && time.Since(latest.CreatedAt) < OTPCooldownDuration {
		return domain.ErrOTPCooldown
	}

	otp, err := helper.GenerateOTP()
	if err != nil {
		return err
	}

	otpHash := helper.HashOTP(otp)

	txFn := func(uow domain.AuthUnitOfWork) error {
		if err := uow.Verifications().DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}
		_, err := uow.Verifications().CreateToken(
			ctx,
			&domain.EmailVerificationToken{
				UserID:    user.ID,
				TokenHash: []byte(otpHash),
				ExpiresAt: time.Now().Add(OTPExpirationDuration),
			},
		)
		return err
	}

	if s.txManager != nil {
		if err := s.txManager.WithinTransaction(ctx, txFn); err != nil {
			return err
		}
	} else {
		if err := s.verifications.DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}
		_, err = s.verifications.CreateToken(
			ctx,
			&domain.EmailVerificationToken{
				UserID:    user.ID,
				TokenHash: []byte(otpHash),
				ExpiresAt: time.Now().Add(OTPExpirationDuration),
			},
		)
		if err != nil {
			return err
		}
	}

	if err := s.emailSender.SendOTP(
		ctx,
		user.Email,
		user.FullName,
		otp,
	); err != nil {
		slog.Error("failed to dispatch verification email", "email", user.Email, "err", err)
	}

	return nil
}

func (s *AuthService) ForgotPassword(
	ctx context.Context,
	in dto.ForgotPasswordInput,
) error {
	email := normalize(in.Email)
	if email == "" {
		return domain.ErrInvalidInput
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal whether an email exists.
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return err
	}

	latest, err := s.passwordResets.GetLatestByUserID(ctx, user.ID)
	if err == nil && latest != nil && time.Since(latest.CreatedAt) < OTPCooldownDuration {
		// Keep the public behavior indistinguishable from a nonexistent account.
		return nil
	}

	otp, err := helper.GenerateOTP()
	if err != nil {
		return err
	}

	otpHash := helper.HashOTP(otp)

	txFn := func(uow domain.AuthUnitOfWork) error {
		if err := uow.PasswordResets().DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}
		_, err := uow.PasswordResets().CreateToken(
			ctx,
			&domain.PasswordResetToken{
				UserID:    user.ID,
				TokenHash: []byte(otpHash),
				ExpiresAt: time.Now().Add(OTPExpirationDuration),
			},
		)
		return err
	}

	if s.txManager != nil {
		if err := s.txManager.WithinTransaction(ctx, txFn); err != nil {
			return err
		}
	} else {
		// Remove previous reset tokens so only the latest OTP remains valid.
		if err := s.passwordResets.DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}

		_, err = s.passwordResets.CreateToken(
			ctx,
			&domain.PasswordResetToken{
				UserID:    user.ID,
				TokenHash: []byte(otpHash),
				ExpiresAt: time.Now().Add(OTPExpirationDuration),
			},
		)
		if err != nil {
			return err
		}
	}

	if err := s.emailSender.SendPasswordResetOTP(
		ctx,
		user.Email,
		user.FullName,
		otp,
	); err != nil {
		slog.Error("failed to dispatch password reset email", "email", user.Email, "err", err)
	}

	return nil
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	in dto.ResetPasswordInput,
) error {
	email := normalize(in.Email)
	if email == "" || in.OTP == "" || in.NewPassword == "" {
		return domain.ErrInvalidInput
	}

	if len(in.NewPassword) < 8 {
		return domain.ErrInvalidInput
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	token, err := s.passwordResets.GetActiveByUserID(ctx, user.ID)
	if err != nil {
		return domain.ErrInvalidOTP
	}

	if token.AttemptCount >= MaxOTPAttempts {
		_ = s.passwordResets.DeleteByUserID(ctx, user.ID)
		return domain.ErrOTPAttemptsExceeded
	}

	if !helper.CheckOTPHash(in.OTP, string(token.TokenHash)) {
		token.AttemptCount++
		_ = s.passwordResets.IncrementAttempts(ctx, token.ID)
		if token.AttemptCount >= MaxOTPAttempts {
			_ = s.passwordResets.DeleteByUserID(ctx, user.ID)
			return domain.ErrOTPAttemptsExceeded
		}
		return domain.ErrInvalidOTP
	}

	hash, err := s.hasher.Hash(in.NewPassword)
	if err != nil {
		return err
	}

	txFn := func(uow domain.AuthUnitOfWork) error {
		// Atomically claim the reset token before changing credentials.
		// A concurrent/replayed request will fail this conditional update.
		if err := uow.PasswordResets().MarkUsed(ctx, token.ID); err != nil {
			return err
		}
		if err := uow.Credentials().UpdatePassword(ctx, user.ID, hash); err != nil {
			return err
		}
		_, err := uow.Users().IncrementTokenVersion(ctx, user.ID)
		return err
	}

	if s.txManager != nil {
		return s.txManager.WithinTransaction(ctx, txFn)
	}

	if err := s.passwordResets.MarkUsed(ctx, token.ID); err != nil {
		return err
	}

	if err := s.credentials.UpdatePassword(ctx, user.ID, hash); err != nil {
		return err
	}

	if _, err := s.users.IncrementTokenVersion(ctx, user.ID); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, normalize(email))
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *AuthService) GetGoogleAuthURL(state string) (string, error) {
	if s.oauth == nil || !s.oauth.IsConfigured() {
		return "", domain.ErrOAuthNotConfigured
	}
	return s.oauth.GetAuthURL(state)
}

func (s *AuthService) GoogleCallback(
	ctx context.Context,
	in dto.GoogleCallbackInput,
) (*dto.AuthResult, error) {
	if s.oauth == nil || !s.oauth.IsConfigured() {
		return nil, domain.ErrOAuthNotConfigured
	}

	if in.Code == "" {
		return nil, domain.ErrInvalidInput
	}

	if in.State == "" || in.CookieState == "" || in.State != in.CookieState {
		return nil, domain.ErrInvalidOAuthState
	}

	oauthUser, err := s.oauth.ExchangeCode(ctx, in.Code)
	if err != nil {
		return nil, err
	}

	email := normalize(oauthUser.Email)
	if email == "" || oauthUser.ID == "" {
		return nil, domain.ErrInvalidInput
	}
	if !oauthUser.VerifiedEmail {
		return nil, domain.ErrOAuthEmailNotVerified
	}

	// First try to find an existing user through the external identity.
	userID, err := s.externalIdentity.GetUserID(
		ctx,
		"google",
		oauthUser.ID,
	)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}
	if err == nil {
		user, err := s.users.GetByID(ctx, userID)
		if err != nil {
			return nil, err
		}

		if !user.IsActive {
			return nil, domain.ErrInvalidCredentials
		}

		now := time.Now()
		if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
			return nil, err
		}
		user.LastLoginAt = &now

		token, err := s.generateToken(user)
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

	// No external identity exists yet.
	// Try to find an existing local account by email.
	user, err := s.users.GetByEmail(ctx, email)
	if err == nil {
		if !user.IsActive {
			return nil, domain.ErrInvalidCredentials
		}

		linkFn := func(uow domain.AuthUnitOfWork) error {
			if oauthUser.VerifiedEmail && user.EmailVerifiedAt == nil {
				if err := uow.Users().SetEmailVerified(ctx, user.ID); err != nil {
					return err
				}
				now := time.Now()
				user.EmailVerifiedAt = &now
			}

			_, err := uow.ExternalIdentities().Create(
				ctx,
				&domain.ExternalIdentity{
					UserID:          user.ID,
					Provider:        "google",
					ProviderSubject: oauthUser.ID,
					EmailAtLink:     &email,
				},
			)
			return err
		}

		if s.txManager != nil {
			if err := s.txManager.WithinTransaction(ctx, linkFn); err != nil {
				return nil, err
			}
		} else {
			if oauthUser.VerifiedEmail && user.EmailVerifiedAt == nil {
				if err := s.users.SetEmailVerified(ctx, user.ID); err != nil {
					return nil, err
				}
				now := time.Now()
				user.EmailVerifiedAt = &now
			}

			_, err = s.externalIdentity.Create(
				ctx,
				&domain.ExternalIdentity{
					UserID:          user.ID,
					Provider:        "google",
					ProviderSubject: oauthUser.ID,
					EmailAtLink:     &email,
				},
			)
			if err != nil {
				return nil, err
			}
		}
	} else if errors.Is(err, domain.ErrUserNotFound) {
		// Create a new user for the Google account inside a transaction
		createFn := func(uow domain.AuthUnitOfWork) error {
			var createErr error
			user, createErr = uow.Users().Create(
				ctx,
				&domain.User{
					Email:    email,
					FullName: strings.TrimSpace(oauthUser.Name),
				},
			)
			if createErr != nil {
				return createErr
			}

			if oauthUser.VerifiedEmail {
				if err := uow.Users().SetEmailVerified(ctx, user.ID); err != nil {
					return err
				}
				now := time.Now()
				user.EmailVerifiedAt = &now
			}

			_, createErr = uow.ExternalIdentities().Create(
				ctx,
				&domain.ExternalIdentity{
					UserID:          user.ID,
					Provider:        "google",
					ProviderSubject: oauthUser.ID,
					EmailAtLink:     &email,
				},
			)
			return createErr
		}

		if s.txManager != nil {
			if err := s.txManager.WithinTransaction(ctx, createFn); err != nil {
				return nil, err
			}
		} else {
			user, err = s.users.Create(
				ctx,
				&domain.User{
					Email:    email,
					FullName: strings.TrimSpace(oauthUser.Name),
				},
			)
			if err != nil {
				return nil, err
			}

			if oauthUser.VerifiedEmail {
				if err := s.users.SetEmailVerified(ctx, user.ID); err != nil {
					return nil, err
				}
				now := time.Now()
				user.EmailVerifiedAt = &now
			}

			_, err = s.externalIdentity.Create(
				ctx,
				&domain.ExternalIdentity{
					UserID:          user.ID,
					Provider:        "google",
					ProviderSubject: oauthUser.ID,
					EmailAtLink:     &email,
				},
			)
			if err != nil {
				return nil, err
			}
		}
	} else {
		return nil, err
	}

	now := time.Now()
	if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now

	token, err := s.generateToken(user)
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
