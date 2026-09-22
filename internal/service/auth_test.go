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

type mockEmailSender struct {
	lastOTP string
}

func (m *mockEmailSender) SendOTP(_ context.Context, _, _ string, otp string) error {
	m.lastOTP = otp
	return nil
}

func setupTestAuthService() (*AuthService, *mockUserRepo, *mockVerificationRepo, *mockEmailSender) {
	userRepo := newMockUserRepo()
	verificationRepo := newMockVerificationRepo()
	emailSender := &mockEmailSender{}
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)

	svc := NewAuthService(userRepo, verificationRepo, hasher, jwtMgr, emailSender)
	return svc, userRepo, verificationRepo, emailSender
}

func TestAuthService_Register_Success(t *testing.T) {
	svc, _, _, emailSender := setupTestAuthService()

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
	svc, _, _, _ := setupTestAuthService()

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
	svc, _, _, emailSender := setupTestAuthService()

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
	svc, _, _, _ := setupTestAuthService()

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

func TestAuthService_ResendOTP_Cooldown(t *testing.T) {
	svc, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "cooldown@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Immediate resend should trigger cooldown
	err = svc.ResendOTP(context.Background(), dto.ResendOTPInput{
		Email: "cooldown@example.com",
	})
	if !errors.Is(err, domain.ErrOTPCooldown) {
		t.Fatalf("expected ErrOTPCooldown, got: %v", err)
	}
}
