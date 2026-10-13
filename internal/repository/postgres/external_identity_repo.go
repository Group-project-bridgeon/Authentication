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

var _ domain.ExternalIdentityRepository = (*ExternalIdentityRepo)(nil)

type ExternalIdentityRepo struct {
	q *sqlcdb.Queries
}

func newExternalIdentityRepo(db sqlcdb.DBTX) *ExternalIdentityRepo {
	return &ExternalIdentityRepo{
		q: sqlcdb.New(db),
	}
}

func NewExternalIdentityRepo(pool *pgxpool.Pool) *ExternalIdentityRepo {
	return newExternalIdentityRepo(pool)
}

func (r *ExternalIdentityRepo) Create(
	ctx context.Context,
	identity *domain.ExternalIdentity,
) (*domain.ExternalIdentity, error) {
	row, err := r.q.CreateExternalIdentity(
		ctx,
		sqlcdb.CreateExternalIdentityParams{
			UserID:          identity.UserID,
			Provider:        identity.Provider,
			ProviderSubject: identity.ProviderSubject,
			EmailAtLink:     stringToPgText(valueOrEmpty(identity.EmailAtLink)),
		},
	)
	if err != nil {
		return nil, err
	}

	return toDomainExternalIdentity(row), nil
}

func (r *ExternalIdentityRepo) GetUserID(
	ctx context.Context,
	provider string,
	providerSubject string,
) (uuid.UUID, error) {
	row, err := r.q.GetUserByExternalIdentity(
		ctx,
		sqlcdb.GetUserByExternalIdentityParams{
			Provider:        provider,
			ProviderSubject: providerSubject,
		},
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, domain.ErrUserNotFound
		}
		return uuid.Nil, err
	}

	return row.ID, nil
}

func toDomainExternalIdentity(
	r sqlcdb.IdentityExternalIdentity,
) *domain.ExternalIdentity {
	return &domain.ExternalIdentity{
		ID:              r.ID,
		UserID:          r.UserID,
		Provider:        r.Provider,
		ProviderSubject: r.ProviderSubject,
		EmailAtLink:     pgTextToStringPtr(r.EmailAtLink),
		LinkedAt:        r.LinkedAt.Time,
		LastLoginAt:     pgTimestamptzToTime(r.LastLoginAt),
	}
}

// Keep pgtype imported here if the generated SQLC parameter types
// require it in this repository package.
var _ pgtype.Text
