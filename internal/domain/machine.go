package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const MachineAudience = "catalog-stock-references"
const MachinePermission = "catalog.stock-references:read"
const MaxMachineTTL = 5 * time.Minute
const MaxCredentialAge = 90 * 24 * time.Hour

var ErrMachineClient = errors.New("invalid machine client")
var ErrMachineInput = errors.New("invalid machine request")
var ErrMachineUnavailable = errors.New("machine authentication unavailable")
var ErrMachineOutcomeUnknown = errors.New("machine mutation outcome unknown")

// MachineFailure exposes only safe structured diagnostics, never a raw cause.
type MachineFailure struct {
	SQLState string
	Reason   string
}

func (*MachineFailure) Error() string { return "machine persistence unavailable" }
func (*MachineFailure) Unwrap() error { return ErrMachineUnavailable }

type MachineCredential struct {
	ID        uuid.UUID
	Secret    string
	ExpiresAt time.Time
}

type MachineRepository interface {
	Create(context.Context, uuid.UUID) error
	SetEnabled(context.Context, uuid.UUID, bool) error
	SetGrant(context.Context, uuid.UUID, bool) error
	Rotate(context.Context, uuid.UUID, uuid.UUID, []byte, time.Duration) (time.Time, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID) error
	// Issue serializes authentication with lifecycle changes and releases output
	// only after commit. sign must be local, bounded and free of network calls.
	Issue(context.Context, uuid.UUID, uuid.UUID, []byte, func(time.Time) (string, error)) (string, error)
}
