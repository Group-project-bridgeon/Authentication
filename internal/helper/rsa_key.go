package helper

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("JWT private key path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read JWT private key: %w", err)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("JWT private key must be PEM encoded")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("unexpected content after JWT private key")
	}

	var key *rsa.PrivateKey

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("JWT private key must be RSA")
			}
		}
	default:
		return nil, errors.New("unsupported JWT private key PEM type")
	}

	if err != nil {
		return nil, errors.New("invalid JWT private key encoding")
	}
	if err := validateRSAKey(key); err != nil {
		return nil, err
	}

	return key, nil
}

func validateRSAKey(key *rsa.PrivateKey) error {
	if key == nil || key.N == nil {
		return errors.New("JWT RSA private key is required")
	}
	if key.N.BitLen() < 2048 {
		return errors.New("JWT RSA key must be at least 2048 bits")
	}
	if err := key.Validate(); err != nil {
		return errors.New("invalid JWT RSA private key")
	}
	return nil
}
