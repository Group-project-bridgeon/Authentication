package main

import (
	"log"
	"github.com/group-project/authentication/internal/config"
	"github.com/group-project/authentication/internal/router"
	"github.com/group-project/authentication/internal/handler"
)



func main(){
	env:=config.Load()
	log.Printf("%+v\n", env)

	auth:=handler.NewAuthHandler()

	ro:=router.NewRouter(auth)
	r:=ro.Router()
	

	if 	err:= r.Run(":" + env.ServerPort); err != nil {
		log.Fatal(err)
	}
}