package postgres

import (
	"context"
	"fmt"

	"github.com/group-project/authentication/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.TransactionManager = (*TransactionManager)(nil)
var _ domain.AuthUnitOfWork = (*unitOfWork)(nil)

type TransactionManager struct {
	pool *pgxpool.Pool
}

func NewTransactionManager(pool *pgxpool.Pool) *TransactionManager {
	return &TransactionManager{pool: pool}
}

type unitOfWork struct {
	userRepo             *UserRepo
	credentialRepo       *CredentialRepo
	verificationRepo     *VerificationRepo
	passwordResetRepo    *PasswordResetRepo
	externalIdentityRepo *ExternalIdentityRepo
}

func (u *unitOfWork) Users() domain.UserRepository {
	return u.userRepo
}

func (u *unitOfWork) Credentials() domain.CredentialRepository {
	return u.credentialRepo
}

func (u *unitOfWork) Verifications() domain.EmailVerificationRepository {
	return u.verificationRepo
}

func (u *unitOfWork) PasswordResets() domain.PasswordResetRepository {
	return u.passwordResetRepo
}

func (u *unitOfWork) ExternalIdentities() domain.ExternalIdentityRepository {
	return u.externalIdentityRepo
}

func (tm *TransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(domain.AuthUnitOfWork) error,
) error {
	tx, err := tm.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	uow := &unitOfWork{
		userRepo:             newUserRepo(tx),
		credentialRepo:       newCredentialRepo(tx),
		verificationRepo:     newVerificationRepo(tx),
		passwordResetRepo:    newPasswordResetRepo(tx),
		externalIdentityRepo: newExternalIdentityRepo(tx),
	}

	if err := fn(uow); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
