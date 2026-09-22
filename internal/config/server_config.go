package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTExpiry   time.Duration
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("SERVER_PORT")
	}
	if port == "" {
		port = "8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default-jwt-secret-key-change-in-production"
	}

	jwtExpiryStr := os.Getenv("JWT_EXPIRY")
	jwtExpiry := 24 * time.Hour
	if jwtExpiryStr != "" {
		if parsed, err := time.ParseDuration(jwtExpiryStr); err == nil {
			jwtExpiry = parsed
		}
	}

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		JWTSecret:   jwtSecret,
		JWTExpiry:   jwtExpiry,
	}, nil
}