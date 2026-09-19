package router

import(
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/group-project/authentication/internal/handler"
)

type SetupRouter struct{
	authHandler *handler.AuthHandler
}

func NewRouter(handler *handler.AuthHandler) *SetupRouter {
	return &SetupRouter{
		authHandler : handler,
	}
}



func (s *SetupRouter) Router()*gin.Engine {
	r := gin.Default()

	r.GET("/health",func(c *gin.Context) {
		 c.JSON(http.StatusOK,gin.H{
			"status":"okay",
		})
	})

	r.GET("/login",s.authHandler.Login)

	return r
}