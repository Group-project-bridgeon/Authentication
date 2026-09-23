package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	handler "github.com/group-project/authentication/internal/handler/http"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/middleware"
)

type Route struct {
	authHandler *handler.AuthHandler
	jwtManager  *helper.JWTManager
}

func NewRouter(h *handler.AuthHandler, j *helper.JWTManager) *Route {
	return &Route{
		authHandler: h,
		jwtManager:  j,
	}
}

func (s *Route) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "okay",
		})
	})

	api := r.Group("/api/v1/auth")
	{
		api.POST("/register", s.authHandler.Register)
		api.POST("/login", s.authHandler.Login)
		api.POST("/verify-email", s.authHandler.VerifyEmail)
		api.POST("/resend-otp", s.authHandler.ResendOTP)
		api.POST("/forgot-password", s.authHandler.ForgotPassword)
		api.POST("/reset-password", s.authHandler.ResetPassword)

		// Dedicated JWT protected routes
		protected := api.Group("")
		protected.Use(middleware.JWTAuth(s.jwtManager))
		{
			protected.GET("/me", s.authHandler.Me)
		}
	}

	return r
}