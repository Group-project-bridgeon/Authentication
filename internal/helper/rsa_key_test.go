package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempKeyFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test_key.pem")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("failed to write temp key file: %v", err)
	}
	return path
}

func TestLoadRSAPrivateKey_ValidPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	path := writeTempKeyFile(t, pemBytes)
	loaded, err := LoadRSAPrivateKey(path)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if loaded == nil || loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded key does not match generated key")
	}
}

func TestLoadRSAPrivateKey_ValidPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	path := writeTempKeyFile(t, pemBytes)
	loaded, err := LoadRSAPrivateKey(path)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if loaded == nil || loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded key does not match generated key")
	}
}

func TestLoadRSAPrivateKey_EmptyPathAndMissingFile(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		_, err := LoadRSAPrivateKey("")
		if err == nil || !strings.Contains(err.Error(), "JWT private key path is required") {
			t.Fatalf("expected required path error, got: %v", err)
		}
	})

	t.Run("whitespace path", func(t *testing.T) {
		_, err := LoadRSAPrivateKey("   \t  ")
		if err == nil || !strings.Contains(err.Error(), "JWT private key path is required") {
			t.Fatalf("expected required path error, got: %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		missingPath := filepath.Join(t.TempDir(), "nonexistent.pem")
		_, err := LoadRSAPrivateKey(missingPath)
		if err == nil || !strings.Contains(err.Error(), "read JWT private key") {
			t.Fatalf("expected read error, got: %v", err)
		}
	})
}

func TestLoadRSAPrivateKey_MalformedPEMAndInvalidDER(t *testing.T) {
	t.Run("malformed PEM", func(t *testing.T) {
		path := writeTempKeyFile(t, []byte("this is not a valid pem content at all"))
		_, err := LoadRSAPrivateKey(path)
		if err == nil || !strings.Contains(err.Error(), "JWT private key must be PEM encoded") {
			t.Fatalf("expected PEM encoded error, got: %v", err)
		}
	})

	t.Run("invalid DER PKCS1", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("corrupt-der-bytes-for-pkcs1"),
		})
		path := writeTempKeyFile(t, pemBytes)
		_, err := LoadRSAPrivateKey(path)
		if err == nil || !strings.Contains(err.Error(), "invalid JWT private key encoding") {
			t.Fatalf("expected invalid encoding error, got: %v", err)
		}
	})

	t.Run("invalid DER PKCS8", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("corrupt-der-bytes-for-pkcs8"),
		})
		path := writeTempKeyFile(t, pemBytes)
		_, err := LoadRSAPrivateKey(path)
		if err == nil || !strings.Contains(err.Error(), "invalid JWT private key encoding") {
			t.Fatalf("expected invalid encoding error, got: %v", err)
		}
	})
}

func TestLoadRSAPrivateKey_NonRSAPKCS8Key(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal ecdsa PKCS8: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	path := writeTempKeyFile(t, pemBytes)
	_, err = LoadRSAPrivateKey(path)
	if err == nil || !strings.Contains(err.Error(), "JWT private key must be RSA") {
		t.Fatalf("expected RSA required error, got: %v", err)
	}
}

func TestLoadRSAPrivateKey_UnsupportedPEMType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDer,
	})

	path := writeTempKeyFile(t, pemBytes)
	_, err = LoadRSAPrivateKey(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported JWT private key PEM type") {
		t.Fatalf("expected unsupported PEM type error, got: %v", err)
	}
}

func TestLoadRSAPrivateKey_KeyBelow2048Bits(t *testing.T) {
	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate 1024-bit key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(smallKey),
	})

	path := writeTempKeyFile(t, pemBytes)
	_, err = LoadRSAPrivateKey(path)
	if err == nil || !strings.Contains(err.Error(), "JWT RSA key must be at least 2048 bits") {
		t.Fatalf("expected minimum bits error, got: %v", err)
	}
}

func TestLoadRSAPrivateKey_UnexpectedContentAfterKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	withTrailing := append(pemBytes, []byte("\nextra trailing content")...)
	path := writeTempKeyFile(t, withTrailing)

	_, err = LoadRSAPrivateKey(path)
	if err == nil || !strings.Contains(err.Error(), "unexpected content after JWT private key") {
		t.Fatalf("expected unexpected content error, got: %v", err)
	}
}
