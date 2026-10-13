package domain

import "context"

type AuthUnitOfWork interface {
	Users() UserRepository
	Credentials() CredentialRepository
	Verifications() EmailVerificationRepository
	PasswordResets() PasswordResetRepository
	ExternalIdentities() ExternalIdentityRepository
}

type TransactionManager interface {
	WithinTransaction(
		ctx context.Context,
		fn func(AuthUnitOfWork) error,
	) error
}
