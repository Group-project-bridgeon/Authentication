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

type VerifyEmailInput struct {
	Email string
	OTP   string
}

type ResendOTPInput struct {
	Email string
}

type AuthResult struct {
	User      *domain.User
	Token     string
	TokenType string
	ExpiresIn int64
}

type RegisterResult struct {
	User    *domain.User
	Message string
}