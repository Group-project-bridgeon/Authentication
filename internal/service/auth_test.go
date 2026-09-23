package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/service/dto"
)

type mockUserRepo struct {
	users map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	if _, exists := m.users[u.Email]; exists {
		return nil, domain.ErrEmailTaken
	}
	user := &domain.User{
		ID:           uuid.New(),
		Email:        u.Email,
		Name:         u.Name,
		PasswordHash: u.PasswordHash,
		CreatedAt:    time.Now(),
		IsVerified:   u.IsVerified,
	}
	m.users[user.Email] = user
	return user, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	u, exists := m.users[email]
	if !exists {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *mockUserRepo) SetVerified(_ context.Context, id uuid.UUID) error {
	for _, u := range m.users {
		if u.ID == id {
			u.IsVerified = true
			return nil
		}
	}
	return domain.ErrUserNotFound
}

func (m *mockUserRepo) UpdatePassword(_ context.Context, id uuid.UUID, passwordHash string) error {
	for _, u := range m.users {
		if u.ID == id {
			u.PasswordHash = passwordHash
			u.IsVerified = true
			return nil
		}
	}
	return domain.ErrUserNotFound
}

type mockVerificationRepo struct {
	verifications map[uuid.UUID]*domain.EmailVerification
}

func newMockVerificationRepo() *mockVerificationRepo {
	return &mockVerificationRepo{verifications: make(map[uuid.UUID]*domain.EmailVerification)}
}

func (m *mockVerificationRepo) Upsert(_ context.Context, v *domain.EmailVerification) (*domain.EmailVerification, error) {
	record := &domain.EmailVerification{
		ID:         uuid.New(),
		UserID:     v.UserID,
		OtpHash:    v.OtpHash,
		Attempts:   v.Attempts,
		ExpiresAt:  v.ExpiresAt,
		LastSentAt: time.Now(),
		CreatedAt:  time.Now(),
	}
	m.verifications[v.UserID] = record
	return record, nil
}

func (m *mockVerificationRepo) GetByUserID(_ context.Context, userID uuid.UUID) (*domain.EmailVerification, error) {
	v, exists := m.verifications[userID]
	if !exists {
		return nil, domain.ErrInvalidOTP
	}
	return v, nil
}

func (m *mockVerificationRepo) IncrementAttempts(_ context.Context, userID uuid.UUID) (int, error) {
	v, exists := m.verifications[userID]
	if !exists {
		return 0, domain.ErrInvalidOTP
	}
	v.Attempts++
	return v.Attempts, nil
}

func (m *mockVerificationRepo) DeleteByUserID(_ context.Context, userID uuid.UUID) error {
	delete(m.verifications, userID)
	return nil
}

type mockPasswordResetRepo struct {
	resets map[uuid.UUID]*domain.PasswordReset
}

func newMockPasswordResetRepo() *mockPasswordResetRepo {
	return &mockPasswordResetRepo{resets: make(map[uuid.UUID]*domain.PasswordReset)}
}

func (m *mockPasswordResetRepo) Upsert(_ context.Context, p *domain.PasswordReset) (*domain.PasswordReset, error) {
	record := &domain.PasswordReset{
		ID:         uuid.New(),
		UserID:     p.UserID,
		OtpHash:    p.OtpHash,
		Attempts:   p.Attempts,
		ExpiresAt:  p.ExpiresAt,
		LastSentAt: time.Now(),
		CreatedAt:  time.Now(),
	}
	m.resets[p.UserID] = record
	return record, nil
}

func (m *mockPasswordResetRepo) GetByUserID(_ context.Context, userID uuid.UUID) (*domain.PasswordReset, error) {
	p, exists := m.resets[userID]
	if !exists {
		return nil, domain.ErrInvalidOTP
	}
	return p, nil
}

func (m *mockPasswordResetRepo) IncrementAttempts(_ context.Context, userID uuid.UUID) (int, error) {
	p, exists := m.resets[userID]
	if !exists {
		return 0, domain.ErrInvalidOTP
	}
	p.Attempts++
	return p.Attempts, nil
}

func (m *mockPasswordResetRepo) DeleteByUserID(_ context.Context, userID uuid.UUID) error {
	delete(m.resets, userID)
	return nil
}

type mockEmailSender struct {
	lastOTP          string
	lastResetOTP     string
}

func (m *mockEmailSender) SendOTP(_ context.Context, _, _ string, otp string) error {
	m.lastOTP = otp
	return nil
}

func (m *mockEmailSender) SendPasswordResetOTP(_ context.Context, _, _ string, otp string) error {
	m.lastResetOTP = otp
	return nil
}

func setupTestAuthService() (*AuthService, *mockUserRepo, *mockVerificationRepo, *mockPasswordResetRepo, *mockEmailSender) {
	userRepo := newMockUserRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)

	svc := NewAuthService(userRepo, verificationRepo, resetRepo, hasher, jwtMgr, emailSender)
	return svc, userRepo, verificationRepo, resetRepo, emailSender
}

func TestAuthService_Register_Success(t *testing.T) {
	svc, _, _, _, emailSender := setupTestAuthService()

	res, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "Alice@Example.Com ",
		Name:     " Alice Tester ",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.User.Email != "alice@example.com" {
		t.Errorf("expected normalized email alice@example.com, got %s", res.User.Email)
	}
	if res.User.IsVerified {
		t.Errorf("expected user to be unverified initially")
	}
	if emailSender.lastOTP == "" {
		t.Fatal("expected emailSender to have received an OTP")
	}
}

func TestAuthService_Login_UnverifiedRejection(t *testing.T) {
	svc, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "unverified@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error on register: %v", err)
	}

	_, err = svc.Login(context.Background(), dto.LoginInput{
		Email:    "unverified@example.com",
		Password: "Password123!",
	})
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got: %v", err)
	}
}

func TestAuthService_VerifyEmail_Success(t *testing.T) {
	svc, _, _, _, emailSender := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "verify@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error on register: %v", err)
	}

	sentOTP := emailSender.lastOTP

	authRes, err := svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "verify@example.com",
		OTP:   sentOTP,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying email: %v", err)
	}

	if !authRes.User.IsVerified {
		t.Errorf("expected user to be marked verified")
	}
	if authRes.Token == "" {
		t.Fatal("expected token to be issued on successful verification")
	}

	// Logging in now should succeed!
	loginRes, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "verify@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error logging in after verification: %v", err)
	}
	if loginRes.Token == "" {
		t.Fatal("expected token on login")
	}
}

func TestAuthService_VerifyEmail_WrongOTP(t *testing.T) {
	svc, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "wrongotp@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	_, err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "wrongotp@example.com",
		OTP:   "000000",
	})
	if !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}
}

func TestAuthService_ForgotPassword_MasksNonExistentEmail(t *testing.T) {
	svc, _, _, _, _ := setupTestAuthService()

	err := svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "nonexistent@example.com",
	})
	if err != nil {
		t.Fatalf("expected nil error (masked), got: %v", err)
	}
}

func TestAuthService_ForgotPassword_And_ResetPassword_Success(t *testing.T) {
	svc, _, _, _, emailSender := setupTestAuthService()

	// Register user
	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "reset@example.com",
		Name:     "Reset User",
		Password: "OldPassword123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Request password reset
	err = svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "reset@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected forgot-password error: %v", err)
	}

	resetOTP := emailSender.lastResetOTP
	if resetOTP == "" {
		t.Fatal("expected password reset OTP to be generated and emailed")
	}

	// Reset password with the OTP
	authRes, err := svc.ResetPassword(context.Background(), dto.ResetPasswordInput{
		Email:       "reset@example.com",
		OTP:         resetOTP,
		NewPassword: "NewSecurePassword456!",
	})
	if err != nil {
		t.Fatalf("unexpected reset-password error: %v", err)
	}

	// Verify Auto-Login: token must be present!
	if authRes.Token == "" {
		t.Fatal("expected access token to be returned for auto-login")
	}
	if !authRes.User.IsVerified {
		t.Errorf("expected user to be verified after reset")
	}

	// Verify login with OLD password fails!
	_, err = svc.Login(context.Background(), dto.LoginInput{
		Email:    "reset@example.com",
		Password: "OldPassword123!",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected login with old password to fail with ErrInvalidCredentials, got: %v", err)
	}

	// Verify login with NEW password succeeds!
	newLogin, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "reset@example.com",
		Password: "NewSecurePassword456!",
	})
	if err != nil {
		t.Fatalf("expected login with new password to succeed, got: %v", err)
	}
	if newLogin.Token == "" {
		t.Fatal("expected token on login with new password")
	}
}

func TestAuthService_ResetPassword_WrongOTP(t *testing.T) {
	svc, _, _, _, _ := setupTestAuthService()

	_, _ = svc.Register(context.Background(), dto.RegisterInput{
		Email:    "wrongreset@example.com",
		Name:     "User",
		Password: "Password123!",
	})

	_ = svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "wrongreset@example.com",
	})

	_, err := svc.ResetPassword(context.Background(), dto.ResetPasswordInput{
		Email:       "wrongreset@example.com",
		OTP:         "999999",
		NewPassword: "NewPassword123!",
	})
	if !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}
}
