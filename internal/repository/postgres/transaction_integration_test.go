package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTransactionManager_RollsBackUserInsert(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL rollback integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	email := "rollback-" + uuid.NewString() + "@example.com"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM identity_users WHERE email = $1`, email)
	})

	txManager := NewTransactionManager(pool)
	forcedErr := errors.New("force rollback after user insert")

	err = txManager.WithinTransaction(ctx, func(uow domain.AuthUnitOfWork) error {
		if _, err := uow.Users().Create(ctx, &domain.User{
			Email:    email,
			FullName: "Rollback Test",
		}); err != nil {
			return err
		}

		return forcedErr
	})
	if !errors.Is(err, forcedErr) {
		t.Fatalf("expected forced rollback error, got: %v", err)
	}

	_, err = NewUserRepo(pool).GetByEmail(ctx, email)
	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("expected inserted user to be rolled back, got: %v", err)
	}
}
