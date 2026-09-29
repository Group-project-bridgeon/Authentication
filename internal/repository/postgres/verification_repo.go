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

// compile-time check: VerificationRepo must satisfy domain.VerificationRepository
var _ domain.VerificationRepository = (*VerificationRepo)(nil)

type VerificationRepo struct {
	q *sqlcdb.Queries
}

func NewVerificationRepo(pool *pgxpool.Pool) *VerificationRepo {
	return &VerificationRepo{q: sqlcdb.New(pool)}
}

func (r *VerificationRepo) Upsert(ctx context.Context, v *domain.EmailVerification) (*domain.EmailVerification, error) {
	row, err := r.q.UpsertVerification(ctx, sqlcdb.UpsertVerificationParams{
		UserID:  v.UserID,
		OtpHash: v.OtpHash,
		Attempts: int32(v.Attempts),
		ExpiresAt: pgtype.Timestamptz{
			Time:  v.ExpiresAt,
			Valid: true,
		},
	})
	if err != nil {
		return nil, err
	}
	return toDomainVerification(row), nil
}

func (r *VerificationRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.EmailVerification, error) {
	row, err := r.q.GetVerificationByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidOTP
		}
		return nil, err
	}
	return toDomainVerification(row), nil
}

func (r *VerificationRepo) IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	attempts, err := r.q.IncrementVerificationAttempts(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(attempts), nil
}

func (r *VerificationRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.q.DeleteVerificationByUserID(ctx, userID)
}

func toDomainVerification(r sqlcdb.EmailVerification) *domain.EmailVerification {
	return &domain.EmailVerification{
		ID:         r.ID,
		UserID:     r.UserID,
		OtpHash:    r.OtpHash,
		Attempts:   int(r.Attempts),
		ExpiresAt:  r.ExpiresAt.Time,
		LastSentAt: r.LastSentAt.Time,
		CreatedAt:  r.CreatedAt.Time,
	}
}
