package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/service/dto"
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
	users  domain.UserRepository
	Hasher PasswordHasher
	tokens TokenGenerator
}

func NewAuthService(u domain.UserRepository, h PasswordHasher, t TokenGenerator) *AuthService {
	return &AuthService{users: u, Hasher: h, tokens: t}
}

func normalize(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *AuthService) Register(ctx context.Context, in dto.RegisterInput) (*dto.AuthResult, error) {
	name := strings.TrimSpace(in.Name)
	if len(name) < 2 {
		return nil, domain.ErrInvalidInput
	}

	hash, err := s.Hasher.Hash(in.Password)
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

func (s *AuthService) Login(ctx context.Context, in dto.LoginInput) (*dto.AuthResult, error) {
	u, err := s.users.GetByEmail(ctx, normalize(in.Email))
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, domain.ErrInvalidCredentials // never reveal which part was wrong
	}
	if err != nil {
		return nil, err
	}
	if err := s.Hasher.Compare(u.PasswordHash, in.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
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

func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, normalize(email))
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}
