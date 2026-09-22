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

func TestAuthService_Register_Success(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

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
	if res.User.Name != "Alice Tester" {
		t.Errorf("expected trimmed name 'Alice Tester', got '%s'", res.User.Name)
	}
	if res.Token == "" {
		t.Fatal("expected access token to be generated")
	}
}

func TestAuthService_Register_DuplicateEmail(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "test@example.com",
		Name:     "User One",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = svc.Register(context.Background(), dto.RegisterInput{
		Email:    "TEST@example.com",
		Name:     "User Two",
		Password: "Password123!",
	})
	if !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got: %v", err)
	}
}

func TestAuthService_Register_InvalidWhitespaceName(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "test@example.com",
		Name:     "   ",
		Password: "Password123!",
	})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestAuthService_Login_Success(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

	_, err := svc.Register(context.Background(), dto.RegisterInput{
		Email:    "user@example.com",
		Name:     "User",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error registering: %v", err)
	}

	res, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    " USER@EXAMPLE.COM ",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("unexpected error on login: %v", err)
	}
	if res.Token == "" {
		t.Fatal("expected access token on login")
	}
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

	_, _ = svc.Register(context.Background(), dto.RegisterInput{
		Email:    "user@example.com",
		Name:     "User",
		Password: "Password123!",
	})

	_, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "user@example.com",
		Password: "WrongPassword!",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestAuthService_Login_NonExistentEmail(t *testing.T) {
	repo := newMockUserRepo()
	hasher := helper.NewBcrypt()
	jwtMgr := helper.NewJWTManager("test-jwt-secret-at-least-32-bytes-long", 1*time.Hour)
	svc := NewAuthService(repo, hasher, jwtMgr)

	_, err := svc.Login(context.Background(), dto.LoginInput{
		Email:    "nobody@example.com",
		Password: "Password123!",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}
