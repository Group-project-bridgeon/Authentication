package domain

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"time"
)

const FulfillmentAudience = "inventory-fulfillment"

var fulfillmentScopes = map[string]bool{"inventory.dispatches:create": true, "inventory.dispatches:cancel": true, "inventory.dispatches:read": true}

const ReservationAudience = "inventory-reservations"

var reservationScopes = map[string]bool{
	"inventory.reservations:reserve": true, "inventory.reservations:release": true,
	"inventory.reservations:consume": true, "inventory.reservations:read": true,
}

type MachineAuthority struct {
	Audience    string
	Permissions []string
}

func CatalogAuthority() MachineAuthority {
	return MachineAuthority{MachineAudience, []string{MachinePermission}}
}
func (a MachineAuthority) Validate() error {
	if a.Audience == MachineAudience {
		if len(a.Permissions) == 1 && a.Permissions[0] == MachinePermission {
			return nil
		}
		return ErrMachineInput
	}
	allowed := reservationScopes
	if a.Audience == FulfillmentAudience {
		allowed = fulfillmentScopes
	} else if a.Audience != ReservationAudience {
		return ErrMachineInput
	}
	if len(a.Permissions) < 1 || len(a.Permissions) > len(allowed) {
		return ErrMachineInput
	}
	previous := ""
	for _, p := range a.Permissions {
		if !allowed[p] || p <= previous {
			return ErrMachineInput
		}
		previous = p
	}
	return nil
}
func ParseMachineAuthority(audience, scope string) (MachineAuthority, error) {
	a := MachineAuthority{audience, strings.Split(scope, " ")}
	return a, a.Validate()
}

type ScopedMachineRepository interface {
	IssueFor(context.Context, uuid.UUID, uuid.UUID, []byte, MachineAuthority, func(time.Time) (string, error)) (string, error)
}

type ScopedMachineGrantRepository interface {
	SetAuthorityGrant(context.Context, uuid.UUID, MachineAuthority, bool) error
}
