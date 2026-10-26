package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	db "github.com/group-project/authentication/internal/repository/postgres/sqlcdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MachineRepository struct{ pool *pgxpool.Pool }

func NewMachineRepository(pool *pgxpool.Pool) *MachineRepository { return &MachineRepository{pool} }
func machineError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, domain.ErrMachineClient) || errors.Is(err, domain.ErrMachineInput) {
		return err
	}
	var pg *pgconn.PgError
	state := ""
	if errors.As(err, &pg) {
		state = pg.Code
	}
	return &domain.MachineFailure{SQLState: state, Reason: "database_failure"}
}
func (r *MachineRepository) transaction(ctx context.Context, id uuid.UUID, create bool, fn func(context.Context, *db.Queries, bool) error) error {
	if id == uuid.Nil {
		return domain.ErrMachineInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return machineError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='5s'"); err != nil {
		return machineError(err)
	}
	q := db.New(tx)
	enabled := false
	if create {
		err = q.CreateMachine(ctx, id)
	} else {
		var row db.LockMachineRow
		row, err = q.LockMachine(ctx, id)
		enabled = row.Enabled
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrMachineClient
	}
	if err != nil {
		return machineError(err)
	}
	if err = fn(ctx, q, enabled); err != nil {
		return machineError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.ErrMachineOutcomeUnknown
	}
	return nil
}
func (r *MachineRepository) Create(ctx context.Context, id uuid.UUID) error {
	return r.transaction(ctx, id, true, func(context.Context, *db.Queries, bool) error { return nil })
}
func (r *MachineRepository) SetEnabled(ctx context.Context, id uuid.UUID, value bool) error {
	return r.transaction(ctx, id, false, func(ctx context.Context, q *db.Queries, _ bool) error {
		return q.SetMachineEnabled(ctx, db.SetMachineEnabledParams{ID: id, Enabled: value})
	})
}
func (r *MachineRepository) SetGrant(ctx context.Context, id uuid.UUID, value bool) error {
	return r.transaction(ctx, id, false, func(ctx context.Context, q *db.Queries, _ bool) error {
		if value {
			return q.GrantMachine(ctx, id)
		}
		return q.RevokeMachineGrant(ctx, id)
	})
}
func (r *MachineRepository) Revoke(ctx context.Context, id, credential uuid.UUID) error {
	return r.transaction(ctx, id, false, func(ctx context.Context, q *db.Queries, _ bool) error {
		_, err := q.RevokeMachineCredential(ctx, db.RevokeMachineCredentialParams{MachineID: id, ID: credential})
		return err
	})
}
func (r *MachineRepository) Rotate(ctx context.Context, id, credential uuid.UUID, hash []byte, age time.Duration) (time.Time, error) {
	if credential == uuid.Nil || len(hash) != 32 || age < time.Second || age > domain.MaxCredentialAge {
		return time.Time{}, domain.ErrMachineInput
	}
	var expiry time.Time
	err := r.transaction(ctx, id, false, func(ctx context.Context, q *db.Queries, _ bool) error {
		now, err := q.MachineClock(ctx)
		if err != nil {
			return err
		}
		expiry = now.Time.Add(age)
		if err = q.RetireMachineOverlap(ctx, id); err != nil {
			return err
		}
		if err = q.BoundMachineOverlap(ctx, id); err != nil {
			return err
		}
		return q.InsertMachineCredential(ctx, db.InsertMachineCredentialParams{ID: credential, MachineID: id, SecretHash: hash, CreatedAt: now, ExpiresAt: pgtype.Timestamptz{Time: expiry, Valid: true}})
	})
	if err != nil {
		return time.Time{}, err
	}
	return expiry, nil
}
func (r *MachineRepository) Issue(ctx context.Context, id, credential uuid.UUID, hash []byte, sign func(time.Time) (string, error)) (string, error) {
	var token string
	err := r.transaction(ctx, id, false, func(ctx context.Context, q *db.Queries, enabled bool) error {
		row, err := q.GetMachineCredential(ctx, db.GetMachineCredentialParams{MachineID: id, ID: credential})
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrMachineClient
		}
		if err != nil {
			return err
		}
		now, err := q.MachineClock(ctx)
		if err != nil {
			return err
		}
		granted, err := q.MachineHasGrant(ctx, id)
		if err != nil {
			return err
		}
		valid := subtle.ConstantTimeCompare(row.SecretHash, hash) == 1
		if !enabled || !granted || !valid || row.RevokedAt.Valid || !now.Time.Before(row.ExpiresAt.Time) {
			return domain.ErrMachineClient
		}
		token, err = sign(now.Time)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
