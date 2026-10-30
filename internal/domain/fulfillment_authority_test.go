package domain

import "testing"

func TestExactFulfillmentAuthority(t *testing.T) {
	for _, scope := range []string{"inventory.dispatches:create", "inventory.dispatches:cancel inventory.dispatches:create inventory.dispatches:read", "inventory.dispatches:read"} {
		a, e := ParseMachineAuthority(FulfillmentAudience, scope)
		if e != nil || a.Validate() != nil {
			t.Fatal("exact subset rejected")
		}
	}
	for _, scope := range []string{"inventory.dispatches", "inventory.dispatches:dispatch", "inventory.deliveries:update", "inventory.dispatches:create-draft", "inventory.dispatches:create inventory.dispatches:cancel", "inventory.dispatches:read inventory.dispatches:read", "catalog.stock-references:read"} {
		if _, e := ParseMachineAuthority(FulfillmentAudience, scope); e == nil {
			t.Fatal("unapproved authority accepted")
		}
	}
}
