package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ExternalIdentity struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Provider        string
	ProviderSubject string
	EmailAtLink     *string
	LinkedAt        time.Time
	LastLoginAt     *time.Time
}

type ExternalIdentityRepository interface {
	Create(ctx context.Context, identity *ExternalIdentity) (*ExternalIdentity, error)
	GetUserID(ctx context.Context, provider string, providerSubject string) (uuid.UUID, error)
}
