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

var _ domain.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

type RefreshTokenRepo struct {
	q *sqlcdb.Queries
}

func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{
		q: sqlcdb.New(pool),
	}
}

func (r *RefreshTokenRepo) Create(
	ctx context.Context,
	token *domain.RefreshToken,
) (*domain.RefreshToken, error) {
	row, err := r.q.CreateRefreshToken(
		ctx,
		sqlcdb.CreateRefreshTokenParams{
			UserID:          token.UserID,
			FamilyID:        token.FamilyID,
			TokenHash:       token.TokenHash,
			UserAgent:       stringToPgText(valueOrEmpty(token.UserAgent)),
			IpAddress:       token.IPAddress,
			ExpiresAt:       pgtype.Timestamptz{Time: token.ExpiresAt, Valid: true},
			FamilyExpiresAt: pgtype.Timestamptz{Time: token.FamilyExpiresAt, Valid: true},
		},
	)
	if err != nil {
		return nil, err
	}

	return toDomainRefreshToken(row), nil
}

func (r *RefreshTokenRepo) GetByHash(
	ctx context.Context,
	tokenHash []byte,
) (*domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return toDomainRefreshToken(row), nil
}

func (r *RefreshTokenRepo) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return toDomainRefreshToken(row), nil
}

func (r *RefreshTokenRepo) GetFamily(
	ctx context.Context,
	familyID uuid.UUID,
) ([]*domain.RefreshToken, error) {
	rows, err := r.q.GetRefreshTokenFamily(ctx, familyID)
	if err != nil {
		return nil, err
	}

	tokens := make([]*domain.RefreshToken, 0, len(rows))

	for _, row := range rows {
		tokens = append(tokens, toDomainRefreshToken(row))
	}

	return tokens, nil
}

func (r *RefreshTokenRepo) Rotate(
	ctx context.Context,
	id uuid.UUID,
	replacedByID uuid.UUID,
) error {
	return r.q.RotateRefreshToken(
		ctx,
		sqlcdb.RotateRefreshTokenParams{
			ID:           id,
			ReplacedByID: pgtype.UUID{Bytes: replacedByID, Valid: true},
		},
	)
}

func (r *RefreshTokenRepo) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason string,
) error {
	return r.q.RevokeRefreshToken(
		ctx,
		sqlcdb.RevokeRefreshTokenParams{
			ID:            id,
			RevokedReason: stringToPgText(reason),
		},
	)
}

func (r *RefreshTokenRepo) RevokeFamily(
	ctx context.Context,
	familyID uuid.UUID,
	reason string,
) error {
	return r.q.RevokeRefreshTokenFamily(
		ctx,
		sqlcdb.RevokeRefreshTokenFamilyParams{
			FamilyID:      familyID,
			RevokedReason: stringToPgText(reason),
		},
	)
}

func (r *RefreshTokenRepo) UpdateLastUsed(
	ctx context.Context,
	id uuid.UUID,
) error {
	return r.q.UpdateRefreshTokenLastUsed(ctx, id)
}

func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context) error {
	return r.q.DeleteExpiredRefreshTokens(ctx)
}

func toDomainRefreshToken(
	r sqlcdb.IdentityRefreshToken,
) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:              r.ID,
		UserID:          r.UserID,
		FamilyID:        r.FamilyID,
		TokenHash:       r.TokenHash,
		ReplacedByID:    pgUUIDToUUID(r.ReplacedByID),
		ReplacedAt:      pgTimestamptzToTime(r.ReplacedAt),
		UserAgent:       pgTextToStringPtr(r.UserAgent),
		IPAddress:       r.IpAddress,
		ExpiresAt:       r.ExpiresAt.Time,
		FamilyExpiresAt: r.FamilyExpiresAt.Time,
		RevokedAt:       pgTimestamptzToTime(r.RevokedAt),
		RevokedReason:   pgTextToStringPtr(r.RevokedReason),
		LastUsedAt:      pgTimestamptzToTime(r.LastUsedAt),
		CreatedAt:       r.CreatedAt.Time,
	}
}
