package service

import (
	"context"
	"errors"
	"strings"

	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/service/dto"
)

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hash, plain string) error
}

type AuthService struct {
	users  domain.UserRepository
	Hasher PasswordHasher
}

func NewAuthService(u domain.UserRepository, h PasswordHasher) *AuthService {
	return &AuthService{users: u, Hasher: h}
}

func normalize(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *AuthService) Register(ctx context.Context, in dto.RegisterInput) (*domain.User, error) {
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	return s.users.Create(ctx, &domain.User{
		Email: normalize(in.Email), Name: strings.TrimSpace(in.Name), PasswordHash: hash,
	})
}

func (s *AuthService) Login(ctx context.Context, in dto.LoginInput) (*domain.User, error) {
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
	return u, nil
}
