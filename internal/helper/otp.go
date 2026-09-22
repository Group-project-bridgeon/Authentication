package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenerateOTP generates a cryptographically secure 6-digit numeric string.
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000) // 0 to 999999
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// HashOTP computes the SHA-256 hash of the plain OTP string.
func HashOTP(otp string) string {
	h := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(h[:])
}

// CheckOTPHash verifies whether the plain OTP matches the stored SHA-256 hash in constant time.
func CheckOTPHash(plainOTP, expectedHash string) bool {
	computed := HashOTP(plainOTP)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedHash)) == 1
}
