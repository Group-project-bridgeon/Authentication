package helper

import (
	"testing"
)

func TestBcrypt_HashAndCompare(t *testing.T) {
	hasher := NewBcrypt()
	plain := "SuperSecret123!"

	hash, err := hasher.Hash(plain)
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}
	if hash == "" || hash == plain {
		t.Fatal("expected secure hashed string")
	}

	if err := hasher.Compare(hash, plain); err != nil {
		t.Fatalf("expected hash to match password: %v", err)
	}

	if err := hasher.Compare(hash, "WrongPassword!"); err == nil {
		t.Fatal("expected error comparing wrong password, got nil")
	}
}
