package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func main(){
	router := gin.Default()

	router.GET("/health",func (c *gin.Context){
		c.JSON(http.StatusOK, gin.H{"status":"ok"})
	})

	if 	err:= router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}