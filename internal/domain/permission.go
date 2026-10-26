package domain

import (
	"context"

	"github.com/google/uuid"
)

type Permission struct {
	Resource string
	Action   string
}

type PermissionRepository interface {
	GetGlobalPermissions(
		ctx context.Context,
		userID uuid.UUID,
	) ([]Permission, error)
}
