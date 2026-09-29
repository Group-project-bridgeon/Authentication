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

// compile-time check: PasswordResetRepo must satisfy domain.PasswordResetRepository
var _ domain.PasswordResetRepository = (*PasswordResetRepo)(nil)

type PasswordResetRepo struct {
	q *sqlcdb.Queries
}

func NewPasswordResetRepo(pool *pgxpool.Pool) *PasswordResetRepo {
	return &PasswordResetRepo{q: sqlcdb.New(pool)}
}

func (r *PasswordResetRepo) Upsert(ctx context.Context, p *domain.PasswordReset) (*domain.PasswordReset, error) {
	row, err := r.q.UpsertPasswordReset(ctx, sqlcdb.UpsertPasswordResetParams{
		UserID:  p.UserID,
		OtpHash: p.OtpHash,
		Attempts: int32(p.Attempts),
		ExpiresAt: pgtype.Timestamptz{
			Time:  p.ExpiresAt,
			Valid: true,
		},
	})
	if err != nil {
		return nil, err
	}
	return toDomainPasswordReset(row), nil
}

func (r *PasswordResetRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.PasswordReset, error) {
	row, err := r.q.GetPasswordResetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidOTP
		}
		return nil, err
	}
	return toDomainPasswordReset(row), nil
}

func (r *PasswordResetRepo) IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	attempts, err := r.q.IncrementPasswordResetAttempts(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(attempts), nil
}

func (r *PasswordResetRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.q.DeletePasswordResetByUserID(ctx, userID)
}

func toDomainPasswordReset(r sqlcdb.PasswordReset) *domain.PasswordReset {
	return &domain.PasswordReset{
		ID:         r.ID,
		UserID:     r.UserID,
		OtpHash:    r.OtpHash,
		Attempts:   int(r.Attempts),
		ExpiresAt:  r.ExpiresAt.Time,
		LastSentAt: r.LastSentAt.Time,
		CreatedAt:  r.CreatedAt.Time,
	}
}
