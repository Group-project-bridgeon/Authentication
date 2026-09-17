package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/group-project/authentication/internal/service"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

func (h *AuthHandler) Register(c *gin.Context) {
	c.JSON(200,gin.H{
		"message":"register endpoint",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	c.JSON(200,gin.H{
		"message":"login endpoin",
	})
}