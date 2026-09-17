package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"github.com/group-project/authentication/internal/config"
)



func main(){
	env:=config.Load()
	log.Printf("%+v\n", env)

	router := gin.Default()

	router.GET("/health",func (c *gin.Context){
		c.JSON(http.StatusOK, gin.H{"status":"ok"})
	})

	if 	err:= router.Run(":" + env.ServerPort); err != nil {
		log.Fatal(err)
	}
}