package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/group-project/authentication/internal/config"
	handler "github.com/group-project/authentication/internal/handler/http"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/platform/database"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/router"
	"github.com/group-project/authentication/internal/service"
	"github.com/joho/godotenv"
)

func run() error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	jwtManager := helper.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiry)
	emailSender := helper.NewEmailSender(cfg.SMTP)
	googleOAuth := helper.NewGoogleOAuthProvider(cfg.GoogleOAuth)
	if googleOAuth.IsConfigured() {
		slog.Info("Google OAuth 2.0 initialized successfully")
	} else {
		slog.Info("Google OAuth 2.0 credentials not configured in .env (OAuth endpoints disabled)")
	}

	usrRepo := postgres.NewUserRepo(pool)
	credentialRepo := postgres.NewCredentialRepo(pool)
	externalIdentityRepo := postgres.NewExternalIdentityRepo(pool)
	verificationRepo := postgres.NewVerificationRepo(pool)
	passwordResetRepo := postgres.NewPasswordResetRepo(pool)
	txManager := postgres.NewTransactionManager(pool)

	authSvc := service.NewAuthService(
		usrRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		passwordResetRepo,
		txManager,
		helper.NewBcrypt(),
		jwtManager,
		emailSender,
		googleOAuth,
	)

	authHandler := handler.NewAuthHandler(authSvc)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.NewRouter(authHandler, jwtManager, authSvc).Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server listening", "port", cfg.Port)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
