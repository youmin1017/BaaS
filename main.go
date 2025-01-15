package main

import (
	"baas-auth/internal/configs"
	"baas-auth/internal/router"
	"baas-auth/internal/services"
)

func main() {
	config := configs.LoadConfig()
	service := services.InitService(config)

	cli := router.InitAPI(config, service)

	cli.Run()
}
