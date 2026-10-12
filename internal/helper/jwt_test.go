package helper

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTManager_GenerateAndValidate(t *testing.T) {
	manager := NewJWTManager("test-secret-key-1234567890123456", 1*time.Hour)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager.Generate(userID, email)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := manager.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected userID %v, got %v", userID, claims.UserID)
	}
	if claims.Email != email {
		t.Errorf("expected email %s, got %s", email, claims.Email)
	}
}

func TestJWTManager_ExpiredToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key-1234567890123456", -1*time.Minute)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager.Generate(userID, email)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	_, err = manager.Validate(token)
	if err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken, got: %v", err)
	}
}

func TestJWTManager_InvalidSignature(t *testing.T) {
	manager1 := NewJWTManager("test-secret-key-1234567890123456", 1*time.Hour)
	manager2 := NewJWTManager("different-secret-key-abcdefghij", 1*time.Hour)

	token, err := manager1.Generate(uuid.New(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	_, err = manager2.Validate(token)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}
