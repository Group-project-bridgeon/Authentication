package domain

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type AuthEvent struct {
	ID             uuid.UUID
	UserID         *uuid.UUID
	EmailAttempted *string
	EventType      string
	IPAddress      *netip.Addr
	UserAgent      *string
	RequestID      *string
	CreatedAt      time.Time
}

type AuthEventRepository interface {
	Create(
		ctx context.Context,
		event *AuthEvent,
	) (*AuthEvent, error)

	GetByID(
		ctx context.Context,
		id uuid.UUID,
	) (*AuthEvent, error)

	GetUserEvents(
		ctx context.Context,
		userID uuid.UUID,
	) ([]*AuthEvent, error)

	GetByType(
		ctx context.Context,
		eventType string,
	) ([]*AuthEvent, error)

	GetRecent(
		ctx context.Context,
		limit int32,
	) ([]*AuthEvent, error)

	DeleteOlderThan(
		ctx context.Context,
		before time.Time,
	) error
}
