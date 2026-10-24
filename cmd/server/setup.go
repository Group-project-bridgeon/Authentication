package main

import (
	"context"
	"crypto/tls"
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
	"github.com/rs/zerolog"
)

func run() error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	privateKey, err := helper.LoadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		return err
	}

	jwtManager, err := helper.NewJWTManager(
		privateKey,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		cfg.JWTExpiry,
	)
	if err != nil {
		return err
	}

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

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
	permissionRepo := postgres.NewPermissionRepo(pool)
	txManager := postgres.NewTransactionManager(pool)

	authSvc := service.NewAuthService(
		usrRepo,
		credentialRepo,
		externalIdentityRepo,
		verificationRepo,
		passwordResetRepo,
		permissionRepo,
		txManager,
		helper.NewBcrypt(),
		jwtManager,
		emailSender,
		googleOAuth,
	)

	authHandler := handler.NewAuthHandler(authSvc)
	machineService, err := service.NewMachineService(postgres.NewMachineRepository(pool), privateKey, cfg.JWTIssuer, cfg.MachineJWTExpiry)
	if err != nil {
		return err
	}
	machineHandler := handler.NewMachineHandler(machineService, zerolog.New(os.Stderr).With().Timestamp().Logger())

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.NewRouter(authHandler, jwtManager, authSvc, pool).WithMachineHandler(machineHandler).Router(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server listening", "port", cfg.Port)
		if cfg.TLSCertPath != "" {
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
		} else {
			errCh <- srv.ListenAndServe()
		}
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
