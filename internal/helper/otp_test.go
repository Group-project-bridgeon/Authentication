package helper

import (
	"regexp"
	"testing"
)

func TestGenerateOTP(t *testing.T) {
	numericRegex := regexp.MustCompile(`^\d{6}$`)

	for i := 0; i < 50; i++ {
		otp, err := GenerateOTP()
		if err != nil {
			t.Fatalf("unexpected error generating OTP: %v", err)
		}
		if !numericRegex.MatchString(otp) {
			t.Errorf("expected 6-digit numeric string, got %q", otp)
		}
	}
}

func TestOTP_HashAndVerify(t *testing.T) {
	otp := "654321"
	hash := HashOTP(otp)

	if len(hash) != 64 {
		t.Fatalf("expected 64-character hex SHA-256 hash, got length %d", len(hash))
	}

	if !CheckOTPHash(otp, hash) {
		t.Fatal("expected matching OTP to verify successfully")
	}

	if CheckOTPHash("123456", hash) {
		t.Fatal("expected mismatched OTP to fail verification")
	}
}
