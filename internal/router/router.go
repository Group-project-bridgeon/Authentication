package router

import(
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/group-project/authentication/internal/handler/http"
)

type Route struct{
	authHandler *handler.AuthHandler
}

func NewRouter(handler *handler.AuthHandler) *Route {
	return &Route{
		authHandler : handler,
	}
}



func (s *Route) Router()*gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/health",func(c *gin.Context) {
		 c.JSON(http.StatusOK,gin.H{
			"status":"okay",
		})
	})

	api := r.Group("/api/v1/auth")
	api.POST("/register", s.authHandler.Register)
	api.POST("/login", s.authHandler.Login)

	return r
}