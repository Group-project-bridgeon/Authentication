package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/group-project/authentication/internal/domain"
	hdto "github.com/group-project/authentication/internal/handler/dto"
	"github.com/group-project/authentication/internal/middleware"
	"github.com/group-project/authentication/internal/service"
	"github.com/group-project/authentication/internal/service/dto"
)

type AuthHandler struct {
	auth *service.AuthService
}

func NewAuthHandler(a *service.AuthService) *AuthHandler {
	return &AuthHandler{auth: a}
}

func toUserResponse(u *domain.User) hdto.UserResponse {
	return hdto.UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: u.CreatedAt,
	}
}

func toAuthResponse(res *dto.AuthResult) hdto.AuthResponse {
	return hdto.AuthResponse{
		User:        toUserResponse(res.User),
		AccessToken: res.Token,
		TokenType:   res.TokenType,
		ExpiresIn:   res.ExpiresIn,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req hdto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	result, err := h.auth.Register(c.Request.Context(), dto.RegisterInput{
		Email:    req.Email,
		Name:     req.Name,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailTaken) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		if errors.Is(err, domain.ErrInvalidInput) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name must contain at least 2 non-whitespace characters"})
			return
		}
		slog.Error("register failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, toAuthResponse(result))
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req hdto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	result, err := h.auth.Login(c.Request.Context(), dto.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			return
		}
		slog.Error("login failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, toAuthResponse(result))
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	u, err := h.auth.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		slog.Error("get current user failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, toUserResponse(u))
}