package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

// compile-time check: UserRepo must satisfy domain.UserRepository
var _ domain.UserRepository = (*UserRepo)(nil)

type UserRepo struct {
	q *sqlcdb.Queries
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{q: sqlcdb.New(pool)}
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) (*domain.User, error) {
	row, err := r.q.CreateUser(ctx, sqlcdb.CreateUserParams{
		Email:        u.Email,
		Name:         u.Name,
		PasswordHash: u.PasswordHash,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, domain.ErrEmailTaken
		}
		return nil, err
	}
	return toDomain(row), nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

func (r *UserRepo) SetVerified(ctx context.Context, id uuid.UUID) error {
	return r.q.SetUserVerified(ctx, id)
}

func (r *UserRepo) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return r.q.UpdatePasswordHashAndVerify(ctx, sqlcdb.UpdatePasswordHashAndVerifyParams{
		ID:           id,
		PasswordHash: passwordHash,
	})
}

func toDomain(r sqlcdb.User) *domain.User {
	return &domain.User{
		ID:           r.ID,
		Email:        r.Email,
		Name:         r.Name,
		PasswordHash: r.PasswordHash,
		CreatedAt:    r.CreatedAt.Time,
		IsVerified:   r.IsVerified,
	}
}