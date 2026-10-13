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

	now := time.Now()
	user := &domain.User{
		ID:                 uuid.New(),
		Email:              u.Email,
		FullName:           u.FullName,
		IsActive:           true,
		MustChangePassword: u.MustChangePassword,
		TokenVersion:       u.TokenVersion,
		CreatedAt:          now,
		UpdatedAt:          now,
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

func (m *mockUserRepo) SetEmailVerified(_ context.Context, id uuid.UUID) error {
	for _, u := range m.users {
		if u.ID == id {
			now := time.Now()
			u.EmailVerifiedAt = &now
			u.UpdatedAt = now
			return nil
		}
	}
	return domain.ErrUserNotFound
}

func (m *mockUserRepo) UpdateLastLogin(_ context.Context, id uuid.UUID, loginAt time.Time) error {
	for _, u := range m.users {
		if u.ID == id {
			u.LastLoginAt = &loginAt
			u.UpdatedAt = loginAt
			return nil
		}
	}
	return domain.ErrUserNotFound
}

type mockCredentialRepo struct {
	credentials map[uuid.UUID]*domain.Credential
}

func newMockCredentialRepo() *mockCredentialRepo {
	return &mockCredentialRepo{
		credentials: make(map[uuid.UUID]*domain.Credential),
	}
}

func (m *mockCredentialRepo) Create(
	_ context.Context,
	c *domain.Credential,
) (*domain.Credential, error) {
	now := time.Now()
	record := &domain.Credential{
		ID:                uuid.New(),
		UserID:            c.UserID,
		PasswordHash:      c.PasswordHash,
		PasswordChangedAt: &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	m.credentials[c.UserID] = record
	return record, nil
}

func (m *mockCredentialRepo) GetByUserID(
	_ context.Context,
	userID uuid.UUID,
) (*domain.Credential, error) {
	c, exists := m.credentials[userID]
	if !exists {
		return nil, domain.ErrInvalidCredentials
	}
	return c, nil
}

func (m *mockCredentialRepo) UpdatePassword(
	_ context.Context,
	userID uuid.UUID,
	passwordHash string,
) error {
	c, exists := m.credentials[userID]
	if !exists {
		return domain.ErrInvalidCredentials
	}

	now := time.Now()
	c.PasswordHash = &passwordHash
	c.PasswordChangedAt = &now
	c.UpdatedAt = now
	c.FailedLoginCount = 0
	c.LockedUntil = nil
	return nil
}

type mockExternalIdentityRepo struct {
	identities map[string]*domain.ExternalIdentity
}

func newMockExternalIdentityRepo() *mockExternalIdentityRepo {
	return &mockExternalIdentityRepo{
		identities: make(map[string]*domain.ExternalIdentity),
	}
}

func externalIdentityKey(provider, subject string) string {
	return provider + ":" + subject
}

func (m *mockExternalIdentityRepo) Create(
	_ context.Context,
	identity *domain.ExternalIdentity,
) (*domain.ExternalIdentity, error) {
	key := externalIdentityKey(identity.Provider, identity.ProviderSubject)

	if _, exists := m.identities[key]; exists {
		return nil, domain.ErrEmailTaken
	}

	record := &domain.ExternalIdentity{
		ID:              uuid.New(),
		UserID:          identity.UserID,
		Provider:        identity.Provider,
		ProviderSubject: identity.ProviderSubject,
		EmailAtLink:     identity.EmailAtLink,
		LinkedAt:        time.Now(),
		LastLoginAt:     identity.LastLoginAt,
	}

	m.identities[key] = record
	return record, nil
}

func (m *mockExternalIdentityRepo) GetUserID(
	_ context.Context,
	provider string,
	providerSubject string,
) (uuid.UUID, error) {
	record, exists := m.identities[externalIdentityKey(provider, providerSubject)]
	if !exists {
		return uuid.Nil, domain.ErrUserNotFound
	}
	return record.UserID, nil
}

type mockVerificationRepo struct {
	verifications map[uuid.UUID]*domain.EmailVerificationToken
}

func newMockVerificationRepo() *mockVerificationRepo {
	return &mockVerificationRepo{
		verifications: make(map[uuid.UUID]*domain.EmailVerificationToken),
	}
}

func (m *mockVerificationRepo) CreateToken(
	_ context.Context,
	token *domain.EmailVerificationToken,
) (*domain.EmailVerificationToken, error) {
	record := &domain.EmailVerificationToken{
		ID:         uuid.New(),
		UserID:     token.UserID,
		TokenHash:  append([]byte(nil), token.TokenHash...),
		ExpiresAt:  token.ExpiresAt,
		VerifiedAt: nil,
		CreatedAt:  time.Now(),
	}

	m.verifications[record.ID] = record
	return record, nil
}

func (m *mockVerificationRepo) GetByHash(
	_ context.Context,
	tokenHash []byte,
) (*domain.EmailVerificationToken, error) {
	for _, token := range m.verifications {
		if token.VerifiedAt == nil &&
			time.Now().Before(token.ExpiresAt) &&
			string(token.TokenHash) == string(tokenHash) {
			return token, nil
		}
	}
	return nil, domain.ErrInvalidOTP
}

func (m *mockVerificationRepo) GetLatestByUserID(
	_ context.Context,
	userID uuid.UUID,
) (*domain.EmailVerificationToken, error) {
	var latest *domain.EmailVerificationToken

	for _, token := range m.verifications {
		if token.UserID != userID || token.VerifiedAt != nil {
			continue
		}
		if latest == nil || token.CreatedAt.After(latest.CreatedAt) {
			latest = token
		}
	}

	if latest == nil {
		return nil, domain.ErrInvalidOTP
	}

	return latest, nil
}

func (m *mockVerificationRepo) GetActiveByUserID(
	_ context.Context,
	userID uuid.UUID,
) (*domain.EmailVerificationToken, error) {
	var latest *domain.EmailVerificationToken

	for _, token := range m.verifications {
		if token.UserID != userID || token.VerifiedAt != nil || time.Now().After(token.ExpiresAt) {
			continue
		}
		if latest == nil || token.CreatedAt.After(latest.CreatedAt) {
			latest = token
		}
	}

	if latest == nil {
		return nil, domain.ErrInvalidOTP
	}

	cp := *latest
	return &cp, nil
}

func (m *mockVerificationRepo) IncrementAttempts(
	_ context.Context,
	id uuid.UUID,
) error {
	token, exists := m.verifications[id]
	if !exists {
		return domain.ErrInvalidOTP
	}
	token.AttemptCount++
	return nil
}

func (m *mockVerificationRepo) MarkUsed(
	_ context.Context,
	id uuid.UUID,
) error {
	token, exists := m.verifications[id]
	if !exists {
		return domain.ErrInvalidOTP
	}

	now := time.Now()
	token.VerifiedAt = &now
	return nil
}

func (m *mockVerificationRepo) DeleteByUserID(
	_ context.Context,
	userID uuid.UUID,
) error {
	for id, token := range m.verifications {
		if token.UserID == userID {
			delete(m.verifications, id)
		}
	}
	return nil
}

type mockPasswordResetRepo struct {
	resets map[uuid.UUID]*domain.PasswordResetToken
}

func newMockPasswordResetRepo() *mockPasswordResetRepo {
	return &mockPasswordResetRepo{
		resets: make(map[uuid.UUID]*domain.PasswordResetToken),
	}
}

func (m *mockPasswordResetRepo) CreateToken(
	_ context.Context,
	token *domain.PasswordResetToken,
) (*domain.PasswordResetToken, error) {
	record := &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    token.UserID,
		TokenHash: append([]byte(nil), token.TokenHash...),
		ExpiresAt: token.ExpiresAt,
		CreatedAt: time.Now(),
	}

	m.resets[record.ID] = record
	return record, nil
}

func (m *mockPasswordResetRepo) GetByHash(
	_ context.Context,
	tokenHash []byte,
) (*domain.PasswordResetToken, error) {
	for _, token := range m.resets {
		if token.UsedAt == nil &&
			time.Now().Before(token.ExpiresAt) &&
			string(token.TokenHash) == string(tokenHash) {
			return token, nil
		}
	}
	return nil, domain.ErrInvalidOTP
}

func (m *mockPasswordResetRepo) GetLatestByUserID(
	_ context.Context,
	userID uuid.UUID,
) (*domain.PasswordResetToken, error) {
	var latest *domain.PasswordResetToken

	for _, token := range m.resets {
		if token.UserID != userID || token.UsedAt != nil {
			continue
		}
		if latest == nil || token.CreatedAt.After(latest.CreatedAt) {
			latest = token
		}
	}

	if latest == nil {
		return nil, domain.ErrInvalidOTP
	}

	return latest, nil
}

func (m *mockPasswordResetRepo) GetActiveByUserID(
	_ context.Context,
	userID uuid.UUID,
) (*domain.PasswordResetToken, error) {
	var latest *domain.PasswordResetToken

	for _, token := range m.resets {
		if token.UserID != userID || token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
			continue
		}
		if latest == nil || token.CreatedAt.After(latest.CreatedAt) {
			latest = token
		}
	}

	if latest == nil {
		return nil, domain.ErrInvalidOTP
	}

	cp := *latest
	return &cp, nil
}

func (m *mockPasswordResetRepo) IncrementAttempts(
	_ context.Context,
	id uuid.UUID,
) error {
	token, exists := m.resets[id]
	if !exists {
		return domain.ErrInvalidOTP
	}
	token.AttemptCount++
	return nil
}

func (m *mockPasswordResetRepo) MarkUsed(
	_ context.Context,
	id uuid.UUID,
) error {
	token, exists := m.resets[id]
	if !exists {
		return domain.ErrInvalidOTP
	}

	now := time.Now()
	token.UsedAt = &now
	return nil
}

func (m *mockPasswordResetRepo) DeleteByUserID(
	_ context.Context,
	userID uuid.UUID,
) error {
	for id, token := range m.resets {
		if token.UserID == userID {
			delete(m.resets, id)
		}
	}
	return nil
}

type mockEmailSender struct {
	lastOTP      string
	lastResetOTP string
}

func (m *mockEmailSender) SendOTP(
	_ context.Context,
	_, _, otp string,
) error {
	m.lastOTP = otp
	return nil
}

func (m *mockEmailSender) SendPasswordResetOTP(
	_ context.Context,
	_, _, otp string,
) error {
	m.lastResetOTP = otp
	return nil
}

type mockOAuthProvider struct {
	authURL    string
	oauthUser  *helper.OAuthUser
	err        error
	configured bool
}

func (m *mockOAuthProvider) GetAuthURL(state string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.authURL + "?state=" + state, nil
}

func (m *mockOAuthProvider) ExchangeCode(
	_ context.Context,
	_ string,
) (*helper.OAuthUser, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.oauthUser, nil
}

func (m *mockOAuthProvider) IsConfigured() bool {
	return m.configured
}

func setupTestAuthServiceWithOAuth() (
	*AuthService,
	*mockUserRepo,
	*mockCredentialRepo,
	*mockExternalIdentityRepo,
	*mockVerificationRepo,
	*mockPasswordResetRepo,
	*mockEmailSender,
	*mockOAuthProvider,
) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}

	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager(
		"test-jwt-secret-at-least-32-bytes-long",
		time.Hour,
	)

	oauthProvider := &mockOAuthProvider{
		authURL: "https://accounts.google.com/o/oauth2/auth",
		oauthUser: &helper.OAuthUser{
			ID:            "google-12345",
			Email:         "googleuser@example.com",
			VerifiedEmail: true,
			Name:          "Google User",
		},
		configured: true,
	}

	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		hasher,
		jwtMgr,
		emailSender,
		oauthProvider,
	)

	return svc,
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		emailSender,
		oauthProvider
}

func setupTestAuthService() (
	*AuthService,
	*mockUserRepo,
	*mockCredentialRepo,
	*mockExternalIdentityRepo,
	*mockVerificationRepo,
	*mockPasswordResetRepo,
	*mockEmailSender,
) {
	svc, users, credentials, external, verification, reset, email, _ :=
		setupTestAuthServiceWithOAuth()

	return svc, users, credentials, external, verification, reset, email
}

func TestAuthService_Register_Success(t *testing.T) {
	svc, _, credentials, _, verificationRepo, _, emailSender :=
		setupTestAuthService()

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

	if res.User.FullName != "Alice Tester" {
		t.Errorf("expected full name Alice Tester, got %s", res.User.FullName)
	}

	if res.User.EmailVerifiedAt != nil {
		t.Error("expected user to be unverified initially")
	}

	if emailSender.lastOTP == "" {
		t.Fatal("expected email sender to receive an OTP")
	}

	if _, err := credentials.GetByUserID(context.Background(), res.User.ID); err != nil {
		t.Fatalf("expected credentials to be created: %v", err)
	}

	token, err := verificationRepo.GetLatestByUserID(
		context.Background(),
		res.User.ID,
	)
	if err != nil {
		t.Fatalf("expected verification token: %v", err)
	}

	if len(token.TokenHash) == 0 {
		t.Fatal("expected verification token hash")
	}
}

func TestAuthService_Login_UnverifiedRejection(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

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
	svc, users, _, _, _, _, emailSender := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "verify@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error on register: %v", err)
	}

	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "verify@example.com",
		OTP:   emailSender.lastOTP,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying email: %v", err)
	}

	user, err := users.GetByEmail(context.Background(), "verify@example.com")
	if err != nil {
		t.Fatalf("failed to retrieve user: %v", err)
	}

	if user.EmailVerifiedAt == nil {
		t.Fatal("expected user to be marked verified")
	}

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
	svc, _, _, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "wrongotp@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "wrongotp@example.com",
		OTP:   "000000",
	})

	if !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}
}

func TestAuthService_ForgotPassword_MasksNonExistentEmail(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

	err := svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "nonexistent@example.com",
	})

	if err != nil {
		t.Fatalf("expected nil error for nonexistent email, got: %v", err)
	}
}

func TestAuthService_ForgotPassword_And_ResetPassword_Success(t *testing.T) {
	svc, users, _, _, _, _, emailSender := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "reset@example.com",
		Name:     "Reset User",
		Password: "OldPassword123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Verify the account first so it can log in after the password reset.
	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "reset@example.com",
		OTP:   emailSender.lastOTP,
	})
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

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

	err = svc.ResetPassword(context.Background(), dto.ResetPasswordInput{
		Email:       "reset@example.com",
		OTP:         resetOTP,
		NewPassword: "NewSecurePassword456!",
	})
	if err != nil {
		t.Fatalf("unexpected reset-password error: %v", err)
	}

	user, err := users.GetByEmail(context.Background(), "reset@example.com")
	if err != nil {
		t.Fatalf("failed to retrieve user: %v", err)
	}

	if user.EmailVerifiedAt == nil {
		t.Fatal("password reset should not remove email verification")
	}

	_, err = svc.Login(context.Background(), dto.LoginInput{
		Email:    "reset@example.com",
		Password: "OldPassword123!",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf(
			"expected old password to fail with ErrInvalidCredentials, got: %v",
			err,
		)
	}

	newLogin, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "reset@example.com",
		Password: "NewSecurePassword456!",
	})
	if err != nil {
		t.Fatalf("expected login with new password to succeed: %v", err)
	}

	if newLogin.Token == "" {
		t.Fatal("expected token on login with new password")
	}
}

func TestAuthService_ResetPassword_WrongOTP(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "wrongreset@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	err = svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "wrongreset@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected forgot-password error: %v", err)
	}

	err = svc.ResetPassword(context.Background(), dto.ResetPasswordInput{
		Email:       "wrongreset@example.com",
		OTP:         "999999",
		NewPassword: "NewPassword123!",
	})

	if !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}
}

func TestAuthService_GoogleCallback_NewUser_Success(t *testing.T) {
	svc, users, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-99999",
		Email:         "newoauth@example.com",
		VerifiedEmail: true,
		Name:          "New OAuth User",
	}

	state := "secure-random-state-123"

	res, err := svc.GoogleCallback(
		context.Background(),
		dto.GoogleCallbackInput{
			Code:        "auth-code-abc",
			State:       state,
			CookieState: state,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error on google callback: %v", err)
	}

	if res.Token == "" {
		t.Fatal("expected JWT token for new Google user")
	}

	if res.User.Email != "newoauth@example.com" {
		t.Errorf(
			"expected email newoauth@example.com, got %s",
			res.User.Email,
		)
	}

	if res.User.EmailVerifiedAt == nil {
		t.Fatal("expected Google verified email to be marked verified")
	}

	saved, err := users.GetByEmail(
		context.Background(),
		"newoauth@example.com",
	)
	if err != nil {
		t.Fatalf("expected user to be saved: %v", err)
	}

	userID, err := externalRepo.GetUserID(
		context.Background(),
		"google",
		"google-99999",
	)
	if err != nil {
		t.Fatalf("expected Google identity to be linked: %v", err)
	}

	if userID != saved.ID {
		t.Fatal("expected external identity to reference saved user")
	}
}

func TestAuthService_GoogleCallback_ExistingEmail_LinksAccount(t *testing.T) {
	svc, users, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	existing, err := users.Create(
		context.Background(),
		&domain.User{
			Email:    "existing@example.com",
			FullName: "Existing User",
		},
	)
	if err != nil {
		t.Fatalf("failed to create existing user: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-link-777",
		Email:         "existing@example.com",
		VerifiedEmail: true,
		Name:          "Existing User",
	}

	state := "state-linking-test"

	res, err := svc.GoogleCallback(
		context.Background(),
		dto.GoogleCallbackInput{
			Code:        "auth-code-xyz",
			State:       state,
			CookieState: state,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Token == "" {
		t.Fatal("expected token after linking existing account")
	}

	userID, err := externalRepo.GetUserID(
		context.Background(),
		"google",
		"google-link-777",
	)
	if err != nil {
		t.Fatalf("expected Google identity to be linked: %v", err)
	}

	if userID != existing.ID {
		t.Fatal("expected Google identity to reference existing user")
	}
}

func TestAuthService_GoogleCallback_ExistingExternalIdentity_Login(
	t *testing.T,
) {
	svc, users, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	user, err := users.Create(
		context.Background(),
		&domain.User{
			Email:    "linked@example.com",
			FullName: "Linked User",
		},
	)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	_, err = externalRepo.Create(
		context.Background(),
		&domain.ExternalIdentity{
			UserID:          user.ID,
			Provider:        "google",
			ProviderSubject: "google-existing",
			EmailAtLink:     ptr("linked@example.com"),
		},
	)
	if err != nil {
		t.Fatalf("failed to create external identity: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-existing",
		Email:         "linked@example.com",
		VerifiedEmail: true,
		Name:          "Linked User",
	}

	state := "existing-identity-state"

	res, err := svc.GoogleCallback(
		context.Background(),
		dto.GoogleCallbackInput{
			Code:        "auth-code",
			State:       state,
			CookieState: state,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.User.ID != user.ID {
		t.Fatal("expected existing linked user")
	}

	if res.Token == "" {
		t.Fatal("expected JWT token")
	}
}

func TestAuthService_GoogleCallback_InvalidState(t *testing.T) {
	svc, _, _, _, _, _, _, _ := setupTestAuthServiceWithOAuth()

	_, err := svc.GoogleCallback(
		context.Background(),
		dto.GoogleCallbackInput{
			Code:        "code",
			State:       "state-one",
			CookieState: "state-two-mismatch",
		},
	)

	if !errors.Is(err, domain.ErrInvalidOAuthState) {
		t.Fatalf("expected ErrInvalidOAuthState, got: %v", err)
	}
}

func TestAuthService_Login_RejectsPasswordlessOAuthUser(t *testing.T) {
	svc, users, _, externalRepo, _, _, _, _ :=
		setupTestAuthServiceWithOAuth()

	user, err := users.Create(
		context.Background(),
		&domain.User{
			Email:    "pwless@example.com",
			FullName: "Passwordless User",
		},
	)
	if err != nil {
		t.Fatalf("failed to create OAuth user: %v", err)
	}

	now := time.Now()
	user.EmailVerifiedAt = &now

	_, err = externalRepo.Create(
		context.Background(),
		&domain.ExternalIdentity{
			UserID:          user.ID,
			Provider:        "google",
			ProviderSubject: "google-pwless",
			EmailAtLink:     ptr("pwless@example.com"),
		},
	)
	if err != nil {
		t.Fatalf("failed to create external identity: %v", err)
	}

	_, err = svc.Login(
		context.Background(),
		dto.LoginInput{
			Email:    "pwless@example.com",
			Password: "SomeRandomPassword123!",
		},
	)

	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf(
			"expected ErrInvalidCredentials for passwordless user, got: %v",
			err,
		)
	}
}

func TestAuthService_ResendOTP_ReplacesPreviousToken(t *testing.T) {
	svc, users, _, _, verificationRepo, _, emailSender :=
		setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "resend@example.com",
		Name:     "Resend User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	user, err := users.GetByEmail(
		context.Background(),
		"resend@example.com",
	)
	if err != nil {
		t.Fatalf("failed to retrieve user: %v", err)
	}

	firstOTP := emailSender.lastOTP

	// Backdate initial verification token to simulate elapsed cooldown
	for _, tok := range verificationRepo.verifications {
		if tok.UserID == user.ID {
			tok.CreatedAt = time.Now().Add(-2 * time.Minute)
		}
	}

	err = svc.ResendOTP(
		context.Background(),
		dto.ResendOTPInput{
			Email: "resend@example.com",
		},
	)
	if err != nil {
		t.Fatalf("unexpected resend error: %v", err)
	}

	if emailSender.lastOTP == "" || emailSender.lastOTP == firstOTP {
		t.Fatal("expected a new OTP to be generated")
	}

	if _, err := verificationRepo.GetLatestByUserID(
		context.Background(),
		user.ID,
	); err != nil {
		t.Fatalf("expected a replacement verification token: %v", err)
	}

	if err := svc.VerifyEmail(
		context.Background(),
		dto.VerifyEmailInput{
			Email: "resend@example.com",
			OTP:   firstOTP,
		},
	); !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected old OTP to be invalid, got: %v", err)
	}
}

func TestAuthService_ResendOTP_CooldownEnforced(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "cooldown@example.com",
		Name:     "Cooldown User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Immediately requesting resend should be blocked by cooldown
	err = svc.ResendOTP(context.Background(), dto.ResendOTPInput{
		Email: "cooldown@example.com",
	})
	if !errors.Is(err, domain.ErrOTPCooldown) {
		t.Fatalf("expected ErrOTPCooldown, got: %v", err)
	}
}

func TestAuthService_VerifyEmail_MaxAttemptsExceeded(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "attempts@example.com",
		Name:     "Attempts User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Submit 5 wrong OTPs
	for i := 0; i < 4; i++ {
		err := svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
			Email: "attempts@example.com",
			OTP:   "000000",
		})
		if !errors.Is(err, domain.ErrInvalidOTP) {
			t.Fatalf("attempt %d: expected ErrInvalidOTP, got %v", i+1, err)
		}
	}

	// 5th failed attempt should trigger ErrOTPAttemptsExceeded
	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "attempts@example.com",
		OTP:   "000000",
	})
	if !errors.Is(err, domain.ErrOTPAttemptsExceeded) {
		t.Fatalf("expected ErrOTPAttemptsExceeded on 5th attempt, got: %v", err)
	}
}

func TestAuthService_MultiUser_SameOTP_NoCrossCollision(t *testing.T) {
	svc, _, _, _, verificationRepo, _, _ := setupTestAuthService()

	// Register User 1
	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "user1@example.com",
		Name:     "User One",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("user1 register error: %v", err)
	}

	// Register User 2
	_, err = svc.Register(context.Background(), dto.RegisterInput{
		Email:    "user2@example.com",
		Name:     "User Two",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("user2 register error: %v", err)
	}

	// Force identical OTP hash for both users to test collision immunity
	sameHash := helper.HashOTP("654321")
	for _, tok := range verificationRepo.verifications {
		tok.TokenHash = []byte(sameHash)
	}

	// User 1 verifies with OTP "654321"
	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "user1@example.com",
		OTP:   "654321",
	})
	if err != nil {
		t.Fatalf("user1 verification failed despite correct OTP: %v", err)
	}

	// User 2 verifies with OTP "654321"
	err = svc.VerifyEmail(context.Background(), dto.VerifyEmailInput{
		Email: "user2@example.com",
		OTP:   "654321",
	})
	if err != nil {
		t.Fatalf("user2 verification failed despite correct OTP: %v", err)
	}
}

func ptr(value string) *string {
	return &value
}
