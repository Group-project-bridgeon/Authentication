package config

import (
	"errors"
	"os"
	"strings"
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
	Port              string
	DatabaseURL       string
	JWTPrivateKeyPath string
	JWTIssuer         string
	JWTAudience       string
	JWTExpiry         time.Duration
	SMTP              SMTPConfig
	GoogleOAuth       GoogleOAuthConfig
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

	jwtPrivateKeyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if strings.TrimSpace(jwtPrivateKeyPath) == "" {
		return nil, errors.New("JWT_PRIVATE_KEY_PATH is required")
	}

	jwtIssuer := os.Getenv("JWT_ISSUER")
	if strings.TrimSpace(jwtIssuer) == "" ||
		jwtIssuer != strings.TrimSpace(jwtIssuer) {
		return nil, errors.New("JWT_ISSUER must be nonblank without surrounding whitespace")
	}

	jwtAudience := os.Getenv("JWT_AUDIENCE")
	if strings.TrimSpace(jwtAudience) == "" ||
		jwtAudience != strings.TrimSpace(jwtAudience) {
		return nil, errors.New("JWT_AUDIENCE must be nonblank without surrounding whitespace")
	}

	jwtExpiry := 15 * time.Minute
	if raw := os.Getenv("JWT_EXPIRY"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, errors.New("JWT_EXPIRY must be a valid duration")
		}
		jwtExpiry = parsed
	}

	if jwtExpiry < time.Second || jwtExpiry > 15*time.Minute {
		return nil, errors.New("JWT_EXPIRY must be between 1s and 15m")
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
		Port:              port,
		DatabaseURL:       dbURL,
		JWTPrivateKeyPath: jwtPrivateKeyPath,
		JWTIssuer:         jwtIssuer,
		JWTAudience:       jwtAudience,
		JWTExpiry:         jwtExpiry,
		SMTP:              smtpConfig,
		GoogleOAuth:       googleOAuthConfig,
	}, nil
}
