package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.AuthEventRepository = (*AuthEventRepo)(nil)

type AuthEventRepo struct {
	q *sqlcdb.Queries
}

func NewAuthEventRepo(pool *pgxpool.Pool) *AuthEventRepo {
	return &AuthEventRepo{
		q: sqlcdb.New(pool),
	}
}

func (r *AuthEventRepo) Create(
	ctx context.Context,
	event *domain.AuthEvent,
) (*domain.AuthEvent, error) {
	row, err := r.q.CreateAuthEvent(ctx, sqlcdb.CreateAuthEventParams{
		UserID:         uuidToPgUUID(event.UserID),
		EmailAttempted: stringToPgText(valueOrEmpty(event.EmailAttempted)),
		EventType:      event.EventType,
		IpAddress:      event.IPAddress,
		UserAgent:      stringToPgText(valueOrEmpty(event.UserAgent)),
		RequestID:      stringToPgText(valueOrEmpty(event.RequestID)),
	})
	if err != nil {
		return nil, err
	}

	return toDomainAuthEvent(row), nil
}

func (r *AuthEventRepo) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*domain.AuthEvent, error) {
	row, err := r.q.GetAuthEventByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}

		return nil, err
	}

	return toDomainAuthEvent(row), nil
}

func (r *AuthEventRepo) GetUserEvents(
	ctx context.Context,
	userID uuid.UUID,
) ([]*domain.AuthEvent, error) {
	rows, err := r.q.GetUserAuthEvents(ctx, uuidToPgUUID(&userID))
	if err != nil {
		return nil, err
	}

	events := make([]*domain.AuthEvent, 0, len(rows))

	for _, row := range rows {
		events = append(events, toDomainAuthEvent(row))
	}

	return events, nil
}

func (r *AuthEventRepo) GetByType(
	ctx context.Context,
	eventType string,
) ([]*domain.AuthEvent, error) {
	rows, err := r.q.GetAuthEventsByType(ctx, eventType)
	if err != nil {
		return nil, err
	}

	events := make([]*domain.AuthEvent, 0, len(rows))

	for _, row := range rows {
		events = append(events, toDomainAuthEvent(row))
	}

	return events, nil
}

func (r *AuthEventRepo) GetRecent(
	ctx context.Context,
	limit int32,
) ([]*domain.AuthEvent, error) {
	rows, err := r.q.GetRecentAuthEvents(ctx, limit)
	if err != nil {
		return nil, err
	}

	events := make([]*domain.AuthEvent, 0, len(rows))

	for _, row := range rows {
		events = append(events, toDomainAuthEvent(row))
	}

	return events, nil
}

func (r *AuthEventRepo) DeleteOlderThan(
	ctx context.Context,
	before time.Time,
) error {
	return r.q.DeleteOldAuthEvents(
		ctx,
		pgtype.Timestamptz{
			Time:  before,
			Valid: true,
		},
	)
}

func toDomainAuthEvent(r sqlcdb.IdentityAuthEvent) *domain.AuthEvent {
	return &domain.AuthEvent{
		ID:             r.ID,
		UserID:         pgUUIDToUUID(r.UserID),
		EmailAttempted: pgTextToStringPtr(r.EmailAttempted),
		EventType:      r.EventType,
		IPAddress:      r.IpAddress,
		UserAgent:      pgTextToStringPtr(r.UserAgent),
		RequestID:      pgTextToStringPtr(r.RequestID),
		CreatedAt:      r.CreatedAt.Time,
	}
}

func uuidToPgUUID(value *uuid.UUID) pgtype.UUID {
	if value == nil {
		return pgtype.UUID{}
	}

	return pgtype.UUID{
		Bytes: *value,
		Valid: true,
	}
}
