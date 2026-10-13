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

var _ domain.EmailVerificationRepository = (*VerificationRepo)(nil)

type VerificationRepo struct {
	q *sqlcdb.Queries
}

func newVerificationRepo(db sqlcdb.DBTX) *VerificationRepo {
	return &VerificationRepo{
		q: sqlcdb.New(db),
	}
}

func NewVerificationRepo(pool *pgxpool.Pool) *VerificationRepo {
	return newVerificationRepo(pool)
}

func (r *VerificationRepo) CreateToken(
	ctx context.Context,
	token *domain.EmailVerificationToken,
) (*domain.EmailVerificationToken, error) {
	row, err := r.q.CreateEmailVerificationToken(
		ctx,
		sqlcdb.CreateEmailVerificationTokenParams{
			UserID:    token.UserID,
			TokenHash: token.TokenHash,
			ExpiresAt: pgtype.Timestamptz{
				Time:  token.ExpiresAt,
				Valid: true,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	return toDomainEmailVerificationToken(row), nil
}

func (r *VerificationRepo) GetByHash(
	ctx context.Context,
	tokenHash []byte,
) (*domain.EmailVerificationToken, error) {
	row, err := r.q.GetEmailVerificationTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidInput
		}
		return nil, err
	}

	return toDomainEmailVerificationToken(row), nil
}

func (r *VerificationRepo) GetLatestByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*domain.EmailVerificationToken, error) {
	row, err := r.q.GetEmailVerificationTokenByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidInput
		}
		return nil, err
	}

	return toDomainEmailVerificationToken(row), nil
}

func (r *VerificationRepo) GetActiveByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*domain.EmailVerificationToken, error) {
	row, err := r.q.GetActiveEmailVerificationToken(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidOTP
		}
		return nil, err
	}

	return toDomainEmailVerificationToken(row), nil
}

func (r *VerificationRepo) IncrementAttempts(
	ctx context.Context,
	id uuid.UUID,
) error {
	return r.q.IncrementEmailVerificationAttempts(ctx, id)
}

func (r *VerificationRepo) MarkUsed(
	ctx context.Context,
	id uuid.UUID,
) error {
	return r.q.MarkEmailVerificationTokenUsed(ctx, id)
}

func (r *VerificationRepo) DeleteByUserID(
	ctx context.Context,
	userID uuid.UUID,
) error {
	return r.q.DeleteEmailVerificationTokensByUserID(ctx, userID)
}

func toDomainEmailVerificationToken(
	r sqlcdb.IdentityEmailVerificationToken,
) *domain.EmailVerificationToken {
	return &domain.EmailVerificationToken{
		ID:           r.ID,
		UserID:       r.UserID,
		TokenHash:    r.TokenHash,
		AttemptCount: r.AttemptCount,
		ExpiresAt:    r.ExpiresAt.Time,
		VerifiedAt:   pgTimestamptzToTime(r.VerifiedAt),
		CreatedAt:    r.CreatedAt.Time,
	}
}
