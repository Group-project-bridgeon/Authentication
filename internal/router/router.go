package router

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	handler "github.com/group-project/authentication/internal/handler/http"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/middleware"
)

// DatabaseHealthChecker is satisfied by *pgxpool.Pool directly.
// No wrapper needed.
type DatabaseHealthChecker interface {
	Ping(context.Context) error
}

type Route struct {
	authHandler  *handler.AuthHandler
	jwtManager   *helper.JWTManager
	userProvider middleware.TokenUserProvider
	dbHealth     DatabaseHealthChecker
}

func NewRouter(
	h *handler.AuthHandler,
	j *helper.JWTManager,
	up middleware.TokenUserProvider,
	db DatabaseHealthChecker,
) *Route {
	return &Route{
		authHandler:  h,
		jwtManager:   j,
		userProvider: up,
		dbHealth:     db,
	}
}

func (s *Route) Router() *gin.Engine {
	r := gin.New()

	// Skip noisy probe logs for /health and /ready; keep all other requests logged.
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health", "/ready"},
	}))
	r.Use(gin.Recovery(), middleware.CORS())

	// Liveness probe ΓÇö always 200 while the process is alive.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "okay",
		})
	})

	// Readiness probe ΓÇö 200 when PostgreSQL is reachable, 503 otherwise.
	// Fail-closed: if dbHealth is nil ΓåÆ 503.
	// Never exposes internal error details or connection strings.
	r.GET("/ready", func(c *gin.Context) {
		if s.dbHealth == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		if err := s.dbHealth.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	api := r.Group("/api/v1/auth")
	{
		api.POST("/register", s.authHandler.Register)
		api.POST("/login", s.authHandler.Login)
		api.POST("/verify-email", s.authHandler.VerifyEmail)
		api.POST("/resend-otp", s.authHandler.ResendOTP)
		api.POST("/forgot-password", s.authHandler.ForgotPassword)
		api.POST("/reset-password", s.authHandler.ResetPassword)

		// Google OAuth endpoints
		api.GET("/google/login", s.authHandler.GoogleLogin)
		api.GET("/google/callback", s.authHandler.GoogleCallback)

		// Dedicated JWT protected routes
		protected := api.Group("")
		protected.Use(middleware.JWTAuth(s.jwtManager, s.userProvider))
		{
			protected.GET("/me", s.authHandler.Me)
		}
	}

	return r
}
