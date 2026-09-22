package config

import (
	"errors"
	"os"
)

type Config struct {
	Port        string
	DatabaseURL string
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return &Config{Port: port, DatabaseURL: dbURL}, nil
}