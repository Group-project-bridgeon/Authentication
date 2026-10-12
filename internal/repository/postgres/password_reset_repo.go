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

var _ domain.PasswordResetRepository = (*PasswordResetRepo)(nil)

type PasswordResetRepo struct {
	q *sqlcdb.Queries
}

func NewPasswordResetRepo(pool *pgxpool.Pool) *PasswordResetRepo {
	return &PasswordResetRepo{
		q: sqlcdb.New(pool),
	}
}

func (r *PasswordResetRepo) CreateToken(
	ctx context.Context,
	token *domain.PasswordResetToken,
) (*domain.PasswordResetToken, error) {
	row, err := r.q.CreatePasswordResetToken(
		ctx,
		sqlcdb.CreatePasswordResetTokenParams{
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

	return toDomainPasswordResetToken(row), nil
}

func (r *PasswordResetRepo) GetByHash(
	ctx context.Context,
	tokenHash []byte,
) (*domain.PasswordResetToken, error) {
	row, err := r.q.GetPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidInput
		}
		return nil, err
	}

	return toDomainPasswordResetToken(row), nil
}

func (r *PasswordResetRepo) GetLatestByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*domain.PasswordResetToken, error) {
	row, err := r.q.GetPasswordResetTokenByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidInput
		}
		return nil, err
	}

	return toDomainPasswordResetToken(row), nil
}

func (r *PasswordResetRepo) GetActiveByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*domain.PasswordResetToken, error) {
	row, err := r.q.GetActivePasswordResetToken(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidOTP
		}
		return nil, err
	}

	return toDomainPasswordResetToken(row), nil
}

func (r *PasswordResetRepo) IncrementAttempts(
	ctx context.Context,
	id uuid.UUID,
) error {
	return r.q.IncrementPasswordResetAttempts(ctx, id)
}

func (r *PasswordResetRepo) MarkUsed(
	ctx context.Context,
	id uuid.UUID,
) error {
	return r.q.MarkPasswordResetTokenUsed(ctx, id)
}

func (r *PasswordResetRepo) DeleteByUserID(
	ctx context.Context,
	userID uuid.UUID,
) error {
	return r.q.DeletePasswordResetTokensByUserID(ctx, userID)
}

func toDomainPasswordResetToken(
	r sqlcdb.IdentityPasswordResetToken,
) *domain.PasswordResetToken {
	return &domain.PasswordResetToken{
		ID:           r.ID,
		UserID:       r.UserID,
		TokenHash:    r.TokenHash,
		AttemptCount: r.AttemptCount,
		ExpiresAt:    r.ExpiresAt.Time,
		UsedAt:       pgTimestamptzToTime(r.UsedAt),
		CreatedAt:    r.CreatedAt.Time,
	}
}
