package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

var _ domain.UserRepository = (*UserRepo)(nil)

type UserRepo struct {
	q    *sqlcdb.Queries
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{
		q:    sqlcdb.New(pool),
		pool: pool,
	}
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) (*domain.User, error) {
	row, err := r.q.CreateUser(ctx, sqlcdb.CreateUserParams{
		Email:    u.Email,
		FullName: stringToPgText(u.FullName),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, domain.ErrEmailTaken
		}
		return nil, err
	}

	return toDomainUser(row), nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return toDomainUser(row), nil
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return toDomainUser(row), nil
}

func (r *UserRepo) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.q.MarkEmailVerified(ctx, id)
}

func (r *UserRepo) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginAt time.Time) error {
	_, err := r.pool.Exec(
		ctx,
		`UPDATE identity_users
		 SET last_login_at = $2,
		     updated_at = now()
		 WHERE id = $1`,
		id,
		loginAt,
	)
	return err
}

func toDomainUser(r sqlcdb.IdentityUser) *domain.User {
	return &domain.User{
		ID:                 r.ID,
		Email:              r.Email,
		FullName:           pgTextToString(r.FullName),
		IsActive:           r.IsActive,
		MustChangePassword: r.MustChangePassword,
		TokenVersion:       r.TokenVersion,
		LastLoginAt:        pgTimestamptzToTime(r.LastLoginAt),
		DeactivatedAt:      pgTimestamptzToTime(r.DeactivatedAt),
		DeactivatedBy:      pgUUIDToUUID(r.DeactivatedBy),
		CreatedBy:          pgUUIDToUUID(r.CreatedBy),
		EmailVerifiedAt:    pgTimestamptzToTime(r.EmailVerifiedAt),
		CreatedAt:          r.CreatedAt.Time,
		UpdatedAt:          r.UpdatedAt.Time,
	}
}
