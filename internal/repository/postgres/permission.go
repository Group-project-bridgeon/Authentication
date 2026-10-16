package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.PermissionRepository = (*PermissionRepo)(nil)

type permissionQuerier interface {
	GetUserGlobalPermissions(ctx context.Context, userID uuid.UUID) ([]sqlcdb.IdentityPermission, error)
}

type PermissionRepo struct {
	q permissionQuerier
}

func newPermissionRepo(db sqlcdb.DBTX) *PermissionRepo {
	return &PermissionRepo{
		q: sqlcdb.New(db),
	}
}

func NewPermissionRepo(pool *pgxpool.Pool) *PermissionRepo {
	return newPermissionRepo(pool)
}

func newPermissionRepoWithQuerier(q permissionQuerier) *PermissionRepo {
	return &PermissionRepo{
		q: q,
	}
}

func (r *PermissionRepo) GetGlobalPermissions(
	ctx context.Context,
	userID uuid.UUID,
) ([]domain.Permission, error) {
	rows, err := r.q.GetUserGlobalPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return []domain.Permission{}, nil
	}

	permissions := make([]domain.Permission, len(rows))
	for i, row := range rows {
		permissions[i] = domain.Permission{
			Resource: row.Resource,
			Action:   row.Action,
		}
	}

	return permissions, nil
}
