package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.CredentialRepository = (*CredentialRepo)(nil)

type CredentialRepo struct {
	q *sqlcdb.Queries
}

func NewCredentialRepo(pool *pgxpool.Pool) *CredentialRepo {
	return &CredentialRepo{
		q: sqlcdb.New(pool),
	}
}

func (r *CredentialRepo) Create(
	ctx context.Context,
	credential *domain.Credential,
) (*domain.Credential, error) {
	row, err := r.q.CreateCredentials(
		ctx,
		sqlcdb.CreateCredentialsParams{
			UserID:       credential.UserID,
			PasswordHash: stringToPgText(valueOrEmpty(credential.PasswordHash)),
		},
	)
	if err != nil {
		return nil, err
	}

	return toDomainCredential(row), nil
}

func (r *CredentialRepo) GetByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*domain.Credential, error) {
	row, err := r.q.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return toDomainCredential(row), nil
}

func (r *CredentialRepo) UpdatePassword(
	ctx context.Context,
	userID uuid.UUID,
	passwordHash string,
) error {
	return r.q.UpdatePassword(
		ctx,
		sqlcdb.UpdatePasswordParams{
			UserID:       userID,
			PasswordHash: stringToPgText(passwordHash),
		},
	)
}

func toDomainCredential(r sqlcdb.IdentityCredential) *domain.Credential {
	return &domain.Credential{
		ID:                r.ID,
		UserID:            r.UserID,
		PasswordHash:      pgTextToStringPtr(r.PasswordHash),
		PasswordChangedAt: pgTimestamptzToTime(r.PasswordChangedAt),
		FailedLoginCount:  r.FailedLoginCount,
		LockedUntil:       pgTimestamptzToTime(r.LockedUntil),
		CreatedAt:         r.CreatedAt.Time,
		UpdatedAt:         r.UpdatedAt.Time,
	}
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func pgTextToStringPtr(value pgtype.Text) *string {
	if !value.Valid {
		return nil
	}

	result := value.String
	return &result
}
