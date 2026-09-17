package service 

import (
	"context"
)

type AuthService struct {
}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) Register(ctx context.Context) error {
	return nil 
}

func (s *AuthService) Login(ctx context.Context) error {
	return nil 
}