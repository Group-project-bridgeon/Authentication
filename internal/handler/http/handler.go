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
		ID:         u.ID,
		Email:      u.Email,
		Name:       u.Name,
		CreatedAt:  u.CreatedAt,
		IsVerified: u.IsVerified,
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

	c.JSON(http.StatusCreated, hdto.RegisterResponse{
		Message: result.Message,
		User:    toUserResponse(result.User),
	})
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
		if errors.Is(err, domain.ErrEmailNotVerified) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "email is not verified, please verify your email before logging in",
				"code":  "EMAIL_NOT_VERIFIED",
			})
			return
		}
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

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req hdto.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	result, err := h.auth.VerifyEmail(c.Request.Context(), dto.VerifyEmailInput{
		Email: req.Email,
		OTP:   req.OTP,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidOTP) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired verification code"})
			return
		}
		if errors.Is(err, domain.ErrOTPMaxAttempts) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many invalid attempts, please request a new verification code"})
			return
		}
		if errors.Is(err, domain.ErrAlreadyVerified) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is already verified"})
			return
		}
		slog.Error("verify email failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, toAuthResponse(result))
}

func (h *AuthHandler) ResendOTP(c *gin.Context) {
	var req hdto.ResendOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	err := h.auth.ResendOTP(c.Request.Context(), dto.ResendOTPInput{
		Email: req.Email,
	})
	if err != nil {
		if errors.Is(err, domain.ErrOTPCooldown) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "please wait at least 60 seconds before requesting another code"})
			return
		}
		if errors.Is(err, domain.ErrAlreadyVerified) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is already verified"})
			return
		}
		slog.Error("resend OTP failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "verification code resent to your email",
	})
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