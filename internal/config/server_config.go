package config

import (
	"errors"
	"os"
	"time"
)

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	FromName string
}

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTExpiry   time.Duration
	SMTP        SMTPConfig
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

	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}

	smtpFrom := os.Getenv("SMTP_FROM")
	if smtpFrom == "" {
		smtpFrom = "noreply@example.com"
	}

	smtpFromName := os.Getenv("SMTP_FROM_NAME")
	if smtpFromName == "" {
		smtpFromName = "Authentication Service"
	}

	smtpConfig := SMTPConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     smtpPort,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     smtpFrom,
		FromName: smtpFromName,
	}

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		JWTSecret:   jwtSecret,
		JWTExpiry:   jwtExpiry,
		SMTP:        smtpConfig,
	}, nil
}