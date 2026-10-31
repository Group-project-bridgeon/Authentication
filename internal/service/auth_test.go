package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/service/dto"
)

var (
	testRSAKeyOnce sync.Once
	testRSAKey     *rsa.PrivateKey
)

func getTestRSAKey() *rsa.PrivateKey {
	testRSAKeyOnce.Do(func() {
		var err error
		testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return testRSAKey
}

func testJWTManager() *helper.JWTManager {
	manager, err := helper.NewJWTManager(getTestRSAKey(), "erp-auth", "erp-api", 15*time.Minute)
	if err != nil {
		panic(err)
	}
	return manager
}

type mockUserRepo struct {
	users               map[string]*domain.User
	setEmailVerifiedErr error
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
	if m.setEmailVerifiedErr != nil {
		return m.setEmailVerifiedErr
	}
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

func (m *mockUserRepo) IncrementTokenVersion(_ context.Context, id uuid.UUID) (int32, error) {
	for _, u := range m.users {
		if u.ID == id {
			u.TokenVersion++
			u.UpdatedAt = time.Now()
			return u.TokenVersion, nil
		}
	}
	return 0, domain.ErrUserNotFound
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
	identities   map[string]*domain.ExternalIdentity
	getUserIDErr error
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
	if m.getUserIDErr != nil {
		return uuid.Nil, m.getUserIDErr
	}
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
	if !exists || token.UsedAt != nil || !time.Now().Before(token.ExpiresAt) {
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

type mockAuthUnitOfWork struct {
	users          *mockUserRepo
	credentials    *mockCredentialRepo
	verifications  *mockVerificationRepo
	passwordResets *mockPasswordResetRepo
	external       *mockExternalIdentityRepo
}

func (u *mockAuthUnitOfWork) Users() domain.UserRepository {
	return u.users
}

func (u *mockAuthUnitOfWork) Credentials() domain.CredentialRepository {
	return u.credentials
}

func (u *mockAuthUnitOfWork) Verifications() domain.EmailVerificationRepository {
	return u.verifications
}

func (u *mockAuthUnitOfWork) PasswordResets() domain.PasswordResetRepository {
	return u.passwordResets
}

func (u *mockAuthUnitOfWork) ExternalIdentities() domain.ExternalIdentityRepository {
	return u.external
}

type mockTransactionManager struct {
	uow         *mockAuthUnitOfWork
	shouldError bool
	err         error
}

func (m *mockTransactionManager) WithinTransaction(
	_ context.Context,
	fn func(domain.AuthUnitOfWork) error,
) error {
	if m.shouldError {
		if m.err != nil {
			return m.err
		}
		return errors.New("simulated transaction failure")
	}
	return fn(m.uow)
}

type mockPermissionRepo struct {
	permissions map[uuid.UUID][]domain.Permission
	err         error
	calledWith  uuid.UUID
}

func newMockPermissionRepo() *mockPermissionRepo {
	return &mockPermissionRepo{
		permissions: make(map[uuid.UUID][]domain.Permission),
	}
}

func (m *mockPermissionRepo) GetGlobalPermissions(_ context.Context, userID uuid.UUID) ([]domain.Permission, error) {
	m.calledWith = userID
	if m.err != nil {
		return nil, m.err
	}
	if perms, exists := m.permissions[userID]; exists {
		return perms, nil
	}
	return []domain.Permission{}, nil
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
	permissionRepo := newMockPermissionRepo()
	emailSender := &mockEmailSender{}

	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()

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

	txManager := &mockTransactionManager{
		uow: &mockAuthUnitOfWork{
			users:          userRepo,
			credentials:    credentialRepo,
			verifications:  verificationRepo,
			passwordResets: resetRepo,
			external:       externalIdentityRepo,
		},
	}

	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		permissionRepo,
		txManager,
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

func setupTestAuthServiceWithPermissions() (
	*AuthService,
	*mockUserRepo,
	*mockCredentialRepo,
	*mockExternalIdentityRepo,
	*mockPermissionRepo,
	*helper.JWTManager,
	*mockOAuthProvider,
) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	permissionRepo := newMockPermissionRepo()
	emailSender := &mockEmailSender{}

	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()

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

	txManager := &mockTransactionManager{
		uow: &mockAuthUnitOfWork{
			users:          userRepo,
			credentials:    credentialRepo,
			verifications:  verificationRepo,
			passwordResets: resetRepo,
			external:       externalIdentityRepo,
		},
	}

	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		permissionRepo,
		txManager,
		hasher,
		jwtMgr,
		emailSender,
		oauthProvider,
	)

	return svc, userRepo, credentialRepo, externalIdentityRepo, permissionRepo, jwtMgr, oauthProvider
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

func TestAuthService_ResendOTP_NonexistentEmail_ReturnsNil(t *testing.T) {
	svc, _, _, _, _, _, _ := setupTestAuthService()

	err := svc.ResendOTP(context.Background(), dto.ResendOTPInput{
		Email: "nonexistent@example.com",
	})
	if err != nil {
		t.Fatalf("expected nil to avoid account enumeration, got: %v", err)
	}
}

func TestAuthService_ResendOTP_VerifiedAccount_ReturnsNil(t *testing.T) {
	svc, userRepo, _, _, _, _, _ := setupTestAuthService()

	now := time.Now()
	userRepo.users["verified@example.com"] = &domain.User{
		ID:              uuid.New(),
		Email:           "verified@example.com",
		FullName:        "Verified User",
		IsActive:        true,
		EmailVerifiedAt: &now,
	}

	err := svc.ResendOTP(context.Background(), dto.ResendOTPInput{
		Email: "verified@example.com",
	})
	if err != nil {
		t.Fatalf("expected nil to avoid account enumeration on verified user, got: %v", err)
	}
}

func TestAuthService_ResendOTP_ValidUnverifiedUser_Success(t *testing.T) {
	svc, userRepo, _, _, verificationRepo, _, emailSender := setupTestAuthService()

	uid := uuid.New()
	userRepo.users["unverified@example.com"] = &domain.User{
		ID:              uid,
		Email:           "unverified@example.com",
		FullName:        "Unverified User",
		IsActive:        true,
		EmailVerifiedAt: nil,
	}
	past := time.Now().Add(-2 * time.Minute)
	tokenId := uuid.New()
	verificationRepo.verifications[tokenId] = &domain.EmailVerificationToken{
		ID:        tokenId,
		UserID:    uid,
		TokenHash: []byte("old-hash"),
		ExpiresAt: past,
		CreatedAt: past,
	}

	err := svc.ResendOTP(context.Background(), dto.ResendOTPInput{
		Email: "unverified@example.com",
	})
	if err != nil {
		t.Fatalf("expected successful resend, got: %v", err)
	}
	if emailSender.lastOTP == "" {
		t.Fatal("expected email OTP to be dispatched")
	}
}

func TestAuthService_ResetPassword_IncrementsTokenVersion(t *testing.T) {
	svc, userRepo, credRepo, _, _, resetRepo, _ := setupTestAuthService()

	uid := uuid.New()
	userRepo.users["resetver@example.com"] = &domain.User{
		ID:           uid,
		Email:        "resetver@example.com",
		FullName:     "Reset Ver",
		IsActive:     true,
		TokenVersion: 0,
	}
	oldHash := "old-hash-string"
	credRepo.credentials[uid] = &domain.Credential{
		UserID:       uid,
		PasswordHash: &oldHash,
	}

	otp := "654321"
	otpHash := helper.HashOTP(otp)
	resetId := uuid.New()
	resetRepo.resets[resetId] = &domain.PasswordResetToken{
		ID:        resetId,
		UserID:    uid,
		TokenHash: []byte(otpHash),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	err := svc.ResetPassword(context.Background(), dto.ResetPasswordInput{
		Email:       "resetver@example.com",
		OTP:         otp,
		NewPassword: "NewSecretPassword123!",
	})
	if err != nil {
		t.Fatalf("unexpected reset password error: %v", err)
	}

	user := userRepo.users["resetver@example.com"]
	if user.TokenVersion != 1 {
		t.Errorf("expected TokenVersion to be incremented to 1, got %d", user.TokenVersion)
	}
}

func TestAuthService_Register_TransactionRollbackOnFailure(t *testing.T) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}

	txManager := &mockTransactionManager{
		uow: &mockAuthUnitOfWork{
			users:          userRepo,
			credentials:    credentialRepo,
			verifications:  verificationRepo,
			passwordResets: resetRepo,
			external:       externalIdentityRepo,
		},
		shouldError: true,
	}

	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()
	oauthProvider := &mockOAuthProvider{}

	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		newMockPermissionRepo(),
		txManager,
		hasher,
		jwtMgr,
		emailSender,
		oauthProvider,
	)

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "failtx@example.com",
		Name:     "Fail Tx",
		Password: "Password123!",
	})
	if err == nil {
		t.Fatal("expected error on failed transaction, got nil")
	}

	if emailSender.lastOTP != "" {
		t.Errorf("expected no email dispatched on transaction failure, got %s", emailSender.lastOTP)
	}
}

func TestAuthService_ForgotPassword_CooldownIsMasked(t *testing.T) {
	svc, userRepo, _, _, _, resetRepo, _ := setupTestAuthService()

	uid := uuid.New()
	userRepo.users["cooldown-reset@example.com"] = &domain.User{
		ID:       uid,
		Email:    "cooldown-reset@example.com",
		FullName: "Cooldown Reset",
		IsActive: true,
	}

	resetID := uuid.New()
	resetRepo.resets[resetID] = &domain.PasswordResetToken{
		ID:        resetID,
		UserID:    uid,
		TokenHash: []byte(helper.HashOTP("123456")),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	err := svc.ForgotPassword(context.Background(), dto.ForgotPasswordInput{
		Email: "cooldown-reset@example.com",
	})
	if err != nil {
		t.Fatalf("expected cooldown to be masked with nil, got: %v", err)
	}
}

func TestAuthService_GoogleCallback_RejectsUnverifiedGoogleEmail(t *testing.T) {
	svc, users, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-unverified-1",
		Email:         "unverified-google@example.com",
		VerifiedEmail: false,
		Name:          "Unverified Google User",
	}

	state := "secure-state"
	_, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if !errors.Is(err, domain.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got: %v", err)
	}

	if _, err := users.GetByEmail(context.Background(), "unverified-google@example.com"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("unverified Google email must not create a user, got: %v", err)
	}

	if _, err := externalRepo.GetUserID(context.Background(), "google", "google-unverified-1"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("unverified Google email must not create an external identity, got: %v", err)
	}
}

func TestAuthService_GoogleCallback_UnverifiedEmailDoesNotLinkExistingAccount(t *testing.T) {
	svc, users, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	existing, err := users.Create(context.Background(), &domain.User{
		Email:    "existing-unverified@example.com",
		FullName: "Existing User",
	})
	if err != nil {
		t.Fatalf("failed to create existing user: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-unverified-existing",
		Email:         existing.Email,
		VerifiedEmail: false,
		Name:          "Existing User",
	}

	state := "secure-state-existing"
	_, err = svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if !errors.Is(err, domain.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got: %v", err)
	}

	if _, err := externalRepo.GetUserID(context.Background(), "google", "google-unverified-existing"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("unverified Google email must not be linked, got: %v", err)
	}
}

func TestAuthService_ResetPassword_RejectsReplayedToken(t *testing.T) {
	svc, userRepo, credRepo, _, _, resetRepo, _ := setupTestAuthService()

	uid := uuid.New()
	userRepo.users["replay@example.com"] = &domain.User{
		ID:           uid,
		Email:        "replay@example.com",
		FullName:     "Replay User",
		IsActive:     true,
		TokenVersion: 0,
	}
	oldHash := "old-hash"
	credRepo.credentials[uid] = &domain.Credential{UserID: uid, PasswordHash: &oldHash}

	otp := "654321"
	resetID := uuid.New()
	resetRepo.resets[resetID] = &domain.PasswordResetToken{
		ID:        resetID,
		UserID:    uid,
		TokenHash: []byte(helper.HashOTP(otp)),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	first := dto.ResetPasswordInput{
		Email:       "replay@example.com",
		OTP:         otp,
		NewPassword: "FirstNewPassword123!",
	}
	if err := svc.ResetPassword(context.Background(), first); err != nil {
		t.Fatalf("first reset failed: %v", err)
	}

	second := dto.ResetPasswordInput{
		Email:       "replay@example.com",
		OTP:         otp,
		NewPassword: "SecondNewPassword123!",
	}
	if err := svc.ResetPassword(context.Background(), second); !errors.Is(err, domain.ErrInvalidOTP) {
		t.Fatalf("expected replayed token to fail with ErrInvalidOTP, got: %v", err)
	}

	if userRepo.users["replay@example.com"].TokenVersion != 1 {
		t.Fatalf("replayed token must not increment token version again")
	}
}

// ---------------------------------------------------------------------------
// Section 2: nil OAuth provider must not panic
// ---------------------------------------------------------------------------

func TestAuthService_GoogleCallback_NilOAuthProvider_DoesNotPanic(t *testing.T) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}

	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()

	txManager := &mockTransactionManager{
		uow: &mockAuthUnitOfWork{
			users:          userRepo,
			credentials:    credentialRepo,
			verifications:  verificationRepo,
			passwordResets: resetRepo,
			external:       externalIdentityRepo,
		},
	}

	// Pass nil explicitly as the OAuthProvider.
	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		newMockPermissionRepo(),
		txManager,
		hasher,
		jwtMgr,
		emailSender,
		nil, // nil oauth provider
	)

	state := "some-state"
	_, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if !errors.Is(err, domain.ErrOAuthNotConfigured) {
		t.Fatalf("expected ErrOAuthNotConfigured with nil oauth, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Section 3: external identity DB error must propagate immediately
// ---------------------------------------------------------------------------

func TestAuthService_GoogleCallback_ExternalIdentityDBError_PropagatesImmediately(t *testing.T) {
	svc, userRepo, _, externalRepo, _, _, _, oauthProvider :=
		setupTestAuthServiceWithOAuth()

	dbErr := errors.New("connection reset by peer")
	externalRepo.getUserIDErr = dbErr

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-db-error",
		Email:         "db-error@example.com",
		VerifiedEmail: true,
		Name:          "DB Error User",
	}

	state := "state-db-error"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})

	if !errors.Is(err, dbErr) {
		t.Fatalf("expected db error to propagate, got: %v", err)
	}
	if res != nil {
		t.Fatal("expected nil AuthResult on DB error")
	}

	// Must NOT have created a user.
	if _, lookupErr := userRepo.GetByEmail(context.Background(), "db-error@example.com"); !errors.Is(lookupErr, domain.ErrUserNotFound) {
		t.Fatal("GoogleCallback must not create a user when external identity lookup fails with DB error")
	}

	// Must NOT have linked an external identity (clear the error so we can look up).
	externalRepo.getUserIDErr = nil
	if _, lookupErr := externalRepo.GetUserID(context.Background(), "google", "google-db-error"); !errors.Is(lookupErr, domain.ErrUserNotFound) {
		t.Fatal("GoogleCallback must not link an external identity when DB error occurs")
	}
}

// ---------------------------------------------------------------------------
// Section 4: SetEmailVerified error in fallback path must not be swallowed
// ---------------------------------------------------------------------------

func TestAuthService_GoogleCallback_SetEmailVerifiedError_InFallbackPath(t *testing.T) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}

	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()

	oauthProvider := &mockOAuthProvider{
		authURL: "https://accounts.google.com/o/oauth2/auth",
		oauthUser: &helper.OAuthUser{
			ID:            "google-set-email-err",
			Email:         "set-email-err@example.com",
			VerifiedEmail: true,
			Name:          "SetEmail Error User",
		},
		configured: true,
	}

	// No txManager → forces the non-transaction fallback path.
	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		newMockPermissionRepo(),
		nil, // no txManager → fallback path
		hasher,
		jwtMgr,
		emailSender,
		oauthProvider,
	)

	// Pre-create the local account without email verification.
	existing, err := userRepo.Create(context.Background(), &domain.User{
		Email:    "set-email-err@example.com",
		FullName: "SetEmail Error User",
	})
	if err != nil {
		t.Fatalf("setup: create user: %v", err)
	}
	// EmailVerifiedAt is nil so the code will call SetEmailVerified.

	// Inject the error that SetEmailVerified should return.
	setEmailErr := errors.New("disk write failure")
	userRepo.setEmailVerifiedErr = setEmailErr

	state := "state-set-email-err"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})

	if !errors.Is(err, setEmailErr) {
		t.Fatalf("expected SetEmailVerified error to propagate, got: %v", err)
	}
	if res != nil {
		t.Fatal("expected nil AuthResult when SetEmailVerified fails")
	}

	// External identity must NOT have been linked.
	if _, lookupErr := externalIdentityRepo.GetUserID(
		context.Background(), "google", "google-set-email-err",
	); !errors.Is(lookupErr, domain.ErrUserNotFound) {
		t.Fatal("external identity must not be linked when SetEmailVerified fails")
	}

	// Verify the user was not marked as email-verified (error was injected before that).
	if existing.EmailVerifiedAt != nil {
		t.Fatal("user.EmailVerifiedAt must remain nil when SetEmailVerified fails")
	}
}

func TestAuthService_Login_LoadsPermissionsAndVersion(t *testing.T) {
	svc, userRepo, credentialRepo, _, permissionRepo, jwtMgr, _ := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "loginperms@example.com",
		FullName:        "Login Perms",
		IsActive:        true,
		TokenVersion:    5,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	user.EmailVerifiedAt = &now

	hasher := helper.NewBcrypt()
	hash, err := hasher.Hash("ValidPassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, err = credentialRepo.Create(context.Background(), &domain.Credential{
		UserID:       user.ID,
		PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	permissionRepo.permissions[user.ID] = []domain.Permission{
		{Resource: "catalog", Action: "read"},
		{Resource: "products", Action: "write"},
	}

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "loginperms@example.com",
		Password: "ValidPassword123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if permissionRepo.calledWith != user.ID {
		t.Fatalf("expected permission repo called with %s, got %s", user.ID, permissionRepo.calledWith)
	}

	claims, err := jwtMgr.Validate(res.Token)
	if err != nil {
		t.Fatalf("failed to validate issued token: %v", err)
	}

	if claims.TokenVersion != 5 {
		t.Fatalf("expected token version 5, got %d", claims.TokenVersion)
	}

	expected := []string{"catalog:read", "products:write"}
	if !reflect.DeepEqual(claims.Permissions, expected) {
		t.Fatalf("expected permissions %+v, got %+v", expected, claims.Permissions)
	}
}

func TestAuthService_Login_EmptyPermissionsAllowed(t *testing.T) {
	svc, userRepo, credentialRepo, _, _, jwtMgr, _ := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "emptyperms@example.com",
		FullName:        "Empty Perms",
		IsActive:        true,
		TokenVersion:    1,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	user.EmailVerifiedAt = &now

	hasher := helper.NewBcrypt()
	hash, err := hasher.Hash("ValidPassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, err = credentialRepo.Create(context.Background(), &domain.Credential{
		UserID:       user.ID,
		PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "emptyperms@example.com",
		Password: "ValidPassword123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	claims, err := jwtMgr.Validate(res.Token)
	if err != nil {
		t.Fatalf("failed to validate issued token: %v", err)
	}

	if claims.Permissions == nil || len(claims.Permissions) != 0 {
		t.Fatalf("expected empty permissions slice, got %+v", claims.Permissions)
	}
}

func TestAuthService_Login_PermissionLookupFailure_Fails(t *testing.T) {
	svc, userRepo, credentialRepo, _, permissionRepo, _, _ := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "permlookupfail@example.com",
		FullName:        "Perm Lookup Fail",
		IsActive:        true,
		TokenVersion:    1,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	user.EmailVerifiedAt = &now

	hasher := helper.NewBcrypt()
	hash, err := hasher.Hash("ValidPassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, err = credentialRepo.Create(context.Background(), &domain.Credential{
		UserID:       user.ID,
		PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	dbErr := errors.New("database connection refused during permission lookup")
	permissionRepo.err = dbErr

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "permlookupfail@example.com",
		Password: "ValidPassword123",
	})
	if err == nil {
		t.Fatal("expected login to fail when permission lookup fails, but succeeded")
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected dbErr %v, got: %v", dbErr, err)
	}
	if res != nil {
		t.Fatal("expected nil result on login failure")
	}
}

func TestAuthService_Login_MissingPermissionRepo_Fails(t *testing.T) {
	userRepo := newMockUserRepo()
	credentialRepo := newMockCredentialRepo()
	externalIdentityRepo := newMockExternalIdentityRepo()
	verificationRepo := newMockVerificationRepo()
	resetRepo := newMockPasswordResetRepo()
	emailSender := &mockEmailSender{}
	hasher := helper.NewBcrypt()
	jwtMgr := testJWTManager()

	// Inject nil permission repo
	svc := NewAuthService(
		userRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		resetRepo,
		nil,
		nil,
		hasher,
		jwtMgr,
		emailSender,
		nil,
	)

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "missingpermrepo@example.com",
		FullName:        "Missing Perm Repo",
		IsActive:        true,
		TokenVersion:    1,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	user.EmailVerifiedAt = &now

	hash, _ := hasher.Hash("ValidPassword123")
	_, _ = credentialRepo.Create(context.Background(), &domain.Credential{
		UserID:       user.ID,
		PasswordHash: &hash,
	})

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "missingpermrepo@example.com",
		Password: "ValidPassword123",
	})
	if err == nil {
		t.Fatal("expected error due to missing permission repository, got nil")
	}
	if !strings.Contains(err.Error(), "permission repository is required") {
		t.Fatalf("expected permission repository required error, got: %v", err)
	}
	if res != nil {
		t.Fatal("expected nil result on missing dependency error")
	}
}

func TestAuthService_Login_MalformedPermissionData_Fails(t *testing.T) {
	svc, userRepo, credentialRepo, _, permissionRepo, _, _ := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "malformedperm@example.com",
		FullName:        "Malformed Perm",
		IsActive:        true,
		TokenVersion:    1,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	user.EmailVerifiedAt = &now

	hasher := helper.NewBcrypt()
	hash, err := hasher.Hash("ValidPassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, err = credentialRepo.Create(context.Background(), &domain.Credential{
		UserID:       user.ID,
		PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	permissionRepo.permissions[user.ID] = []domain.Permission{
		{Resource: "bad:colons", Action: "read"},
	}

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "malformedperm@example.com",
		Password: "ValidPassword123",
	})
	if err == nil {
		t.Fatal("expected login to fail with malformed permission data")
	}
	if !errors.Is(err, helper.ErrMalformedPermission) {
		t.Fatalf("expected ErrMalformedPermission, got: %v", err)
	}
	if res != nil {
		t.Fatal("expected nil result on failure")
	}
}

func TestAuthService_GoogleCallback_ExistingUser_LoadsPermissions(t *testing.T) {
	svc, userRepo, _, externalIdentityRepo, permissionRepo, jwtMgr, oauthProvider := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "googleperm@example.com",
		FullName:        "Google Perm User",
		IsActive:        true,
		TokenVersion:    7,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	email := user.Email
	_, err = externalIdentityRepo.Create(context.Background(), &domain.ExternalIdentity{
		UserID:          user.ID,
		Provider:        "google",
		ProviderSubject: "google-perm-subj-1",
		EmailAtLink:     &email,
	})
	if err != nil {
		t.Fatalf("create external identity: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-perm-subj-1",
		Email:         user.Email,
		VerifiedEmail: true,
		Name:          user.FullName,
	}

	permissionRepo.permissions[user.ID] = []domain.Permission{
		{Resource: "catalog", Action: "manage"},
	}

	state := "google-state-1"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if err != nil {
		t.Fatalf("unexpected GoogleCallback error: %v", err)
	}

	claims, err := jwtMgr.Validate(res.Token)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}

	if claims.TokenVersion != 7 {
		t.Fatalf("expected token version 7, got %d", claims.TokenVersion)
	}

	expected := []string{"catalog:manage"}
	if !reflect.DeepEqual(claims.Permissions, expected) {
		t.Fatalf("expected permissions %+v, got %+v", expected, claims.Permissions)
	}
}

func TestAuthService_GoogleCallback_LinkLocalUser_LoadsPermissions(t *testing.T) {
	svc, userRepo, _, _, permissionRepo, jwtMgr, oauthProvider := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "googlelink@example.com",
		FullName:        "Google Link User",
		IsActive:        true,
		TokenVersion:    3,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-link-subj-2",
		Email:         user.Email,
		VerifiedEmail: true,
		Name:          user.FullName,
	}

	permissionRepo.permissions[user.ID] = []domain.Permission{
		{Resource: "inventory", Action: "read"},
	}

	state := "google-state-2"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if err != nil {
		t.Fatalf("unexpected GoogleCallback error: %v", err)
	}

	claims, err := jwtMgr.Validate(res.Token)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}

	if claims.TokenVersion != 3 {
		t.Fatalf("expected token version 3, got %d", claims.TokenVersion)
	}

	expected := []string{"inventory:read"}
	if !reflect.DeepEqual(claims.Permissions, expected) {
		t.Fatalf("expected permissions %+v, got %+v", expected, claims.Permissions)
	}
}

func TestAuthService_GoogleCallback_NewUser_LoadsPermissions(t *testing.T) {
	svc, _, _, _, _, jwtMgr, oauthProvider := setupTestAuthServiceWithPermissions()

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-new-subj-3",
		Email:         "newgoogleuser@example.com",
		VerifiedEmail: true,
		Name:          "New Google User",
	}

	state := "google-state-3"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if err != nil {
		t.Fatalf("unexpected GoogleCallback error: %v", err)
	}

	claims, err := jwtMgr.Validate(res.Token)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}

	if claims.TokenVersion != 0 {
		t.Fatalf("expected token version 0, got %d", claims.TokenVersion)
	}

	if claims.Permissions == nil || len(claims.Permissions) != 0 {
		t.Fatalf("expected empty permissions slice, got %+v", claims.Permissions)
	}
}

func TestAuthService_GoogleCallback_PermissionLookupFailure_Fails(t *testing.T) {
	svc, userRepo, _, externalIdentityRepo, permissionRepo, _, oauthProvider := setupTestAuthServiceWithPermissions()

	now := time.Now()
	user, err := userRepo.Create(context.Background(), &domain.User{
		Email:           "googlelookupfail@example.com",
		FullName:        "Google Lookup Fail",
		IsActive:        true,
		TokenVersion:    1,
		EmailVerifiedAt: &now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	email := user.Email
	_, err = externalIdentityRepo.Create(context.Background(), &domain.ExternalIdentity{
		UserID:          user.ID,
		Provider:        "google",
		ProviderSubject: "google-lookup-fail-subj",
		EmailAtLink:     &email,
	})
	if err != nil {
		t.Fatalf("create external identity: %v", err)
	}

	oauthProvider.oauthUser = &helper.OAuthUser{
		ID:            "google-lookup-fail-subj",
		Email:         user.Email,
		VerifiedEmail: true,
		Name:          user.FullName,
	}

	dbErr := errors.New("permission repository failure during OAuth callback")
	permissionRepo.err = dbErr

	state := "google-state-fail"
	res, err := svc.GoogleCallback(context.Background(), dto.GoogleCallbackInput{
		Code:        "auth-code",
		State:       state,
		CookieState: state,
	})
	if err == nil {
		t.Fatal("expected GoogleCallback to fail when permission lookup fails, but succeeded")
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected dbErr %v, got: %v", dbErr, err)
	}
	if res != nil {
		t.Fatal("expected nil result on failure")
	}
}

func TestAuthService_Login_ManagerPermissionsContract(t *testing.T) {
	svc, userRepo, credentialRepo, _, permissionRepo, jwtMgr, _ := setupTestAuthServiceWithPermissions()
	now := time.Now()

	hasher := helper.NewBcrypt()
	hash, err := hasher.Hash("ValidPassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	t.Run("test admin login yields fresh token satisfying manager verifier", func(t *testing.T) {
		adminUser, err := userRepo.Create(context.Background(), &domain.User{
			Email:           "admin@erp.local",
			FullName:        "Test Admin",
			IsActive:        true,
			TokenVersion:    1,
			EmailVerifiedAt: &now,
		})
		if err != nil {
			t.Fatalf("create admin user: %v", err)
		}
		adminUser.EmailVerifiedAt = &now

		_, err = credentialRepo.Create(context.Background(), &domain.Credential{
			UserID:       adminUser.ID,
			PasswordHash: &hash,
		})
		if err != nil {
			t.Fatalf("create admin credential: %v", err)
		}

		permissionRepo.permissions[adminUser.ID] = []domain.Permission{
			{Resource: "manager.approvals", Action: "approve"},
			{Resource: "manager.approvals", Action: "read"},
			{Resource: "manager.approvals", Action: "reject"},
			{Resource: "manager.approvals", Action: "submit"},
			{Resource: "manager.authz", Action: "check"},
			{Resource: "manager.rbac", Action: "manage"},
		}

		loginRes, err := svc.Login(context.Background(), dto.LoginInput{
			Email:    "admin@erp.local",
			Password: "ValidPassword123",
		})
		if err != nil {
			t.Fatalf("admin login failed: %v", err)
		}

		claims, err := jwtMgr.Validate(loginRes.Token)
		if err != nil {
			t.Fatalf("validate token: %v", err)
		}

		// Verify manager verifier contract
		if claims.UserID != adminUser.ID || claims.Subject != adminUser.ID.String() {
			t.Fatalf("expected user_id equal to sub (%s), got user_id %s, sub %s", adminUser.ID, claims.UserID, claims.Subject)
		}
		if claims.Email != "admin@erp.local" {
			t.Fatalf("expected email admin@erp.local, got %s", claims.Email)
		}
		if claims.TokenVersion != 1 {
			t.Fatalf("expected token_version 1, got %d", claims.TokenVersion)
		}
		if len(claims.Permissions) != 6 {
			t.Fatalf("expected 6 permissions, got %d", len(claims.Permissions))
		}
		for _, p := range claims.Permissions {
			parts := strings.Split(p, ":")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				t.Fatalf("invalid permission format: %s", p)
			}
		}
		lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
		if lifetime <= 0 || lifetime > 15*time.Minute {
			t.Fatalf("expected lifetime <= 15m, got %v", lifetime)
		}
	})

	t.Run("test manager login yields fresh token satisfying manager verifier", func(t *testing.T) {
		managerUser, err := userRepo.Create(context.Background(), &domain.User{
			Email:           "manager@erp.local",
			FullName:        "Test Manager",
			IsActive:        true,
			TokenVersion:    1,
			EmailVerifiedAt: &now,
		})
		if err != nil {
			t.Fatalf("create manager user: %v", err)
		}
		managerUser.EmailVerifiedAt = &now

		_, err = credentialRepo.Create(context.Background(), &domain.Credential{
			UserID:       managerUser.ID,
			PasswordHash: &hash,
		})
		if err != nil {
			t.Fatalf("create manager credential: %v", err)
		}

		permissionRepo.permissions[managerUser.ID] = []domain.Permission{
			{Resource: "manager.approvals", Action: "approve"},
			{Resource: "manager.approvals", Action: "read"},
			{Resource: "manager.approvals", Action: "reject"},
			{Resource: "manager.approvals", Action: "submit"},
		}

		loginRes, err := svc.Login(context.Background(), dto.LoginInput{
			Email:    "manager@erp.local",
			Password: "ValidPassword123",
		})
		if err != nil {
			t.Fatalf("manager login failed: %v", err)
		}

		claims, err := jwtMgr.Validate(loginRes.Token)
		if err != nil {
			t.Fatalf("validate token: %v", err)
		}

		// Verify manager verifier contract
		if claims.UserID != managerUser.ID || claims.Subject != managerUser.ID.String() {
			t.Fatalf("expected user_id equal to sub (%s), got user_id %s, sub %s", managerUser.ID, claims.UserID, claims.Subject)
		}
		if claims.Email != "manager@erp.local" {
			t.Fatalf("expected email manager@erp.local, got %s", claims.Email)
		}
		if claims.TokenVersion != 1 {
			t.Fatalf("expected token_version 1, got %d", claims.TokenVersion)
		}
		if len(claims.Permissions) != 4 {
			t.Fatalf("expected 4 permissions, got %d", len(claims.Permissions))
		}
		for _, p := range claims.Permissions {
			parts := strings.Split(p, ":")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				t.Fatalf("invalid permission format: %s", p)
			}
		}
		lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
		if lifetime <= 0 || lifetime > 15*time.Minute {
			t.Fatalf("expected lifetime <= 15m, got %v", lifetime)
		}
	})
}
