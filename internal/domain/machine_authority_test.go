package domain

import "testing"

func TestMachineAuthorityAllowlist(t *testing.T) {
	for _, tc := range []struct {
		aud, scope string
		valid      bool
	}{{MachineAudience, MachinePermission, true}, {ReservationAudience, "inventory.reservations:reserve", true}, {ReservationAudience, "inventory.reservations:consume inventory.reservations:read inventory.reservations:release inventory.reservations:reserve", true}, {ReservationAudience, "", false}, {ReservationAudience, "inventory.reservations:*", false}, {ReservationAudience, "inventory.reservations:read inventory.reservations:read", false}, {ReservationAudience, "inventory.reservations:reserve inventory.reservations:read", false}, {ReservationAudience, "inventory.reservations:read ", false}, {MachineAudience, "inventory.reservations:reserve", false}, {ReservationAudience, MachinePermission, false}, {"erp-api", MachinePermission, false}} {
		_, err := ParseMachineAuthority(tc.aud, tc.scope)
		if (err == nil) != tc.valid {
			t.Fatal("invalid authority result")
		}
	}
}
