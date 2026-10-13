package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
)

const (
	ContextUserIDKey    = "userID"
	ContextUserEmailKey = "userEmail"
)

type TokenUserProvider interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// JWTAuth returns a Gin middleware dedicated to validating JWT Bearer tokens.
func JWTAuth(jwtManager *helper.JWTManager, userProvider TokenUserProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header is required",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header must be in Bearer {token} format",
			})
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "token is missing",
			})
			return
		}

		claims, err := jwtManager.Validate(tokenString)
		if err != nil {
			if errors.Is(err, helper.ErrExpiredToken) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token has expired",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or malformed token",
			})
			return
		}

		if userProvider == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or revoked token",
			})
			return
		}

		user, err := userProvider.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil || user == nil || !user.IsActive || user.TokenVersion != claims.TokenVersion {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or revoked token",
			})
			return
		}

		// Store user identity in the request context for subsequent handlers
		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextUserEmailKey, claims.Email)

		c.Next()
	}
}

// GetUserID retrieves the authenticated user's ID from the gin context.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(ContextUserIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := val.(uuid.UUID)
	return id, ok
}

// GetUserEmail retrieves the authenticated user's email from the gin context.
func GetUserEmail(c *gin.Context) (string, bool) {
	val, exists := c.Get(ContextUserEmailKey)
	if !exists {
		return "", false
	}
	email, ok := val.(string)
	return email, ok
}
