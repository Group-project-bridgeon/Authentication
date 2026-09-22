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
	_=godotenv.Load()

	cfg, err:= config.Load()
	if err != nil {
		return err
	}

	ctx, stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	usrRepo:=postgres.NewUserRepo(pool)
	authSvc:= service.NewAuthService(usrRepo, helper.NewBcrypt())
	authHandler:= handler.NewAuthHandler(authSvc)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.NewRouter(authHandler).Router(),
		ReadHeaderTimeout: 5 * time.Second,
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