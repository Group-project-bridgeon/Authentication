package config

import (
	"os"
	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort string
}

func Load() Config {
	_ = godotenv.Load()

	return Config{
		ServerPort:os.Getenv("SERVER_PORT"),
	}
}