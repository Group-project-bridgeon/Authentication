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

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTExpiry   time.Duration
	SMTP        SMTPConfig
	GoogleOAuth GoogleOAuthConfig
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
	env := os.Getenv("ENV")
	if env == "" {
		env = os.Getenv("APP_ENV")
	}
	if jwtSecret == "" {
		if env == "production" || env == "prod" {
			return nil, errors.New("JWT_SECRET must be set in production environment")
		}
		jwtSecret = "default-jwt-secret-key-change-in-production"
	}

	jwtExpiryStr := os.Getenv("JWT_EXPIRY")
	jwtExpiry := 15 * time.Minute
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

	googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	if googleRedirectURL == "" {
		googleRedirectURL = "http://localhost:" + port + "/api/v1/auth/google/callback"
	}

	googleOAuthConfig := GoogleOAuthConfig{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  googleRedirectURL,
	}

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		JWTSecret:   jwtSecret,
		JWTExpiry:   jwtExpiry,
		SMTP:        smtpConfig,
		GoogleOAuth: googleOAuthConfig,
	}, nil
}
