package dto

import (
	"github.com/group-project/authentication/internal/domain"
)

type RegisterInput struct {
	Email    string
	Name     string
	Password string
}

type LoginInput struct {
	Email    string
	Password string
}

type AuthResult struct {
	User      *domain.User
	Token     string
	TokenType string
	ExpiresIn int64
}