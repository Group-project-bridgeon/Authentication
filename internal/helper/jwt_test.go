package helper

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestJWTManager(t *testing.T) *JWTManager {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := NewJWTManager(key, "erp-auth", "erp-api", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	return manager
}

func TestJWTManager_GenerateAndValidate(t *testing.T) {
	manager := newTestJWTManager(t)
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

func TestJWTManager_InvalidSignature(t *testing.T) {
	manager1 := newTestJWTManager(t)
	manager2 := newTestJWTManager(t)

	token, err := manager1.Generate(uuid.New(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	_, err = manager2.Validate(token)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}

func TestJWTManager_StrictValidation(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := uuid.New()

	newClaims := func() Claims {
		now := time.Now().UTC().Truncate(time.Second)
		return Claims{
			UserID:       userID,
			TokenVersion: 2,
			Permissions:  []string{"catalog:read"},
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "erp-auth",
				Audience:  jwt.ClaimStrings{"erp-api"},
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
				NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			},
		}
	}

	tests := []struct {
		name   string
		change func(*Claims)
		want   error
	}{
		{"valid", func(c *Claims) {}, nil},
		{"empty permissions", func(c *Claims) {
			c.Permissions = []string{}
		}, nil},
		{"expired", func(c *Claims) {
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second))
		}, ErrExpiredToken},
		{"missing expiry", func(c *Claims) {
			c.ExpiresAt = nil
		}, ErrInvalidToken},
		{"wrong issuer", func(c *Claims) {
			c.Issuer = "other"
		}, ErrInvalidToken},
		{"missing issuer", func(c *Claims) {
			c.Issuer = ""
		}, ErrInvalidToken},
		{"wrong audience", func(c *Claims) {
			c.Audience = jwt.ClaimStrings{"other"}
		}, ErrInvalidToken},
		{"missing audience", func(c *Claims) {
			c.Audience = nil
		}, ErrInvalidToken},
		{"missing issued at", func(c *Claims) {
			c.IssuedAt = nil
		}, ErrInvalidToken},
		{"missing not before", func(c *Claims) {
			c.NotBefore = nil
		}, ErrInvalidToken},
		{"future issued at", func(c *Claims) {
			future := time.Now().Add(30 * time.Second)
			c.IssuedAt = jwt.NewNumericDate(future)
			c.NotBefore = jwt.NewNumericDate(future)
		}, ErrInvalidToken},
		{"future not before", func(c *Claims) {
			c.NotBefore = jwt.NewNumericDate(time.Now().Add(30 * time.Second))
		}, ErrInvalidToken},
		{"invalid time ordering", func(c *Claims) {
			c.NotBefore = jwt.NewNumericDate(c.IssuedAt.Add(-time.Second))
		}, ErrInvalidToken},
		{"excessive lifetime", func(c *Claims) {
			c.ExpiresAt = jwt.NewNumericDate(c.IssuedAt.Add(16 * time.Minute))
		}, ErrInvalidToken},
		{"missing subject", func(c *Claims) {
			c.Subject = ""
		}, ErrInvalidToken},
		{"wrong subject", func(c *Claims) {
			c.Subject = uuid.NewString()
		}, ErrInvalidToken},
		{"zero user ID", func(c *Claims) {
			c.UserID = uuid.Nil
		}, ErrInvalidToken},
		{"negative version", func(c *Claims) {
			c.TokenVersion = -1
		}, ErrInvalidToken},
		{"null permissions", func(c *Claims) {
			c.Permissions = nil
		}, ErrInvalidToken},
		{"malformed permission", func(c *Claims) {
			c.Permissions = []string{"catalog"}
		}, ErrInvalidToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := newClaims()
			tc.change(&claims)

			raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).
				SignedString(manager.privateKey)
			if err != nil {
				t.Fatal(err)
			}

			got, err := manager.Validate(raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.want != nil && got != nil {
				t.Fatal("invalid token returned claims")
			}
		})
	}

	t.Run("missing permissions", func(t *testing.T) {
		data, err := json.Marshal(newClaims())
		if err != nil {
			t.Fatal(err)
		}
		var claims jwt.MapClaims
		if err := json.Unmarshal(data, &claims); err != nil {
			t.Fatal(err)
		}
		delete(claims, "permissions")

		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).
			SignedString(manager.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Validate(raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("want invalid token, got %v", err)
		}
	})
}

func TestJWTManager_RejectsOtherAlgorithms(t *testing.T) {
	manager := newTestJWTManager(t)

	for _, method := range []jwt.SigningMethod{
		jwt.SigningMethodHS256,
		jwt.SigningMethodNone,
	} {
		t.Run(method.Alg(), func(t *testing.T) {
			var key any = []byte("test-only-secret")
			if method == jwt.SigningMethodNone {
				key = jwt.UnsafeAllowNoneSignatureType
			}

			raw, err := jwt.NewWithClaims(method, jwt.MapClaims{}).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Validate(raw); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("want invalid token, got %v", err)
			}
		})
	}
}

func TestJWTManager_GenerateWithPermissions_SuccessAndValidation(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := uuid.New()
	email := "perms@example.com"
	rawPerms := []string{"catalog:read", "products:write"}

	token, err := manager.GenerateWithPermissions(userID, email, 3, rawPerms)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
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
	if claims.TokenVersion != 3 {
		t.Errorf("expected TokenVersion 3, got %d", claims.TokenVersion)
	}
	expected := []string{"catalog:read", "products:write"}
	if !reflect.DeepEqual(claims.Permissions, expected) {
		t.Errorf("expected permissions %+v, got %+v", expected, claims.Permissions)
	}
}

func TestJWTManager_GenerateWithPermissions_DeduplicationAndSorting(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := uuid.New()
	email := "dedup@example.com"
	rawPerms := []string{"products:write", "catalog:read", "products:write", "order:create", "catalog:read"}

	token, err := manager.GenerateWithPermissions(userID, email, 1, rawPerms)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := manager.Validate(token)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	expected := []string{"catalog:read", "order:create", "products:write"}
	if !reflect.DeepEqual(claims.Permissions, expected) {
		t.Fatalf("expected deduplicated and sorted permissions %+v, got %+v", expected, claims.Permissions)
	}
}

func TestJWTManager_GenerateWithPermissions_EmptyGrantsSerializeAsEmptyArray(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := uuid.New()
	email := "empty@example.com"

	token, err := manager.GenerateWithPermissions(userID, email, 0, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := manager.Validate(token)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if claims.Permissions == nil {
		t.Fatal("expected non-nil permissions slice, got nil")
	}
	if len(claims.Permissions) != 0 {
		t.Fatalf("expected 0 permissions, got %d", len(claims.Permissions))
	}

	// Verify JSON serialization produces [] not null
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	if !strings.Contains(string(data), `"permissions":[]`) {
		t.Fatalf("expected JSON to contain '\"permissions\":[]', got %s", string(data))
	}
}

func TestJWTManager_GenerateWithPermissions_MalformedRejections(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := uuid.New()
	email := "malformed@example.com"

	malformedCases := []string{
		"",
		"   ",
		"catalog",
		":action",
		"resource:",
		"resource:action:extra",
		" resource:action",
		"resource:action ",
		"resource :action",
		"resource: action",
	}

	for _, tc := range malformedCases {
		t.Run("input_"+tc, func(t *testing.T) {
			_, err := manager.GenerateWithPermissions(userID, email, 0, []string{tc})
			if !errors.Is(err, ErrMalformedPermission) {
				t.Fatalf("expected ErrMalformedPermission for %q, got: %v", tc, err)
			}
		})
	}
}

func TestNewJWTManager_RejectsNilOrUndersizedKey(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		_, err := NewJWTManager(nil, "erp-auth", "erp-api", 15*time.Minute)
		if err == nil || !strings.Contains(err.Error(), "JWT RSA private key is required") {
			t.Fatalf("expected nil key error, got: %v", err)
		}
	})

	t.Run("undersized key below 2048 bits", func(t *testing.T) {
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewJWTManager(smallKey, "erp-auth", "erp-api", 15*time.Minute)
		if err == nil || !strings.Contains(err.Error(), "JWT RSA key must be at least 2048 bits") {
			t.Fatalf("expected undersized key error, got: %v", err)
		}
	})
}

func TestNewJWTManager_RejectsBlankOrWhitespaceIssuerAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		issuer   string
		audience string
		errMsg   string
	}{
		{"empty issuer", "", "erp-api", "JWT issuer must be nonblank without surrounding whitespace"},
		{"whitespace issuer", "  erp-auth ", "erp-api", "JWT issuer must be nonblank without surrounding whitespace"},
		{"leading space issuer", " erp-auth", "erp-api", "JWT issuer must be nonblank without surrounding whitespace"},
		{"trailing space issuer", "erp-auth ", "erp-api", "JWT issuer must be nonblank without surrounding whitespace"},
		{"empty audience", "erp-auth", "", "JWT audience must be nonblank without surrounding whitespace"},
		{"whitespace audience", "erp-auth", " erp-api ", "JWT audience must be nonblank without surrounding whitespace"},
		{"leading space audience", "erp-auth", " erp-api", "JWT audience must be nonblank without surrounding whitespace"},
		{"trailing space audience", "erp-auth", "erp-api ", "JWT audience must be nonblank without surrounding whitespace"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJWTManager(key, tc.issuer, tc.audience, 15*time.Minute)
			if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
				t.Fatalf("expected error %q, got: %v", tc.errMsg, err)
			}
		})
	}
}

func TestNewJWTManager_RejectsInvalidDuration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"zero duration", 0},
		{"negative duration", -1 * time.Minute},
		{"subsecond duration", 500 * time.Millisecond},
		{"above 15 minutes", 15*time.Minute + time.Second},
		{"one hour", time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJWTManager(key, "erp-auth", "erp-api", tc.duration)
			if err == nil || !strings.Contains(err.Error(), "JWT lifetime must be between 1s and 15m") {
				t.Fatalf("expected lifetime error for duration %v, got: %v", tc.duration, err)
			}
		})
	}
}

func TestJWTManager_GenerateWithPermissions_RejectsNilUUIDAndNegativeVersion(t *testing.T) {
	manager := newTestJWTManager(t)

	t.Run("nil uuid", func(t *testing.T) {
		_, err := manager.GenerateWithPermissions(uuid.Nil, "test@example.com", 0, []string{"catalog:read"})
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for uuid.Nil, got: %v", err)
		}
	})

	t.Run("negative version", func(t *testing.T) {
		_, err := manager.GenerateWithPermissions(uuid.New(), "test@example.com", -1, []string{"catalog:read"})
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for negative version, got: %v", err)
		}
	})
}

func TestJWTManager_TamperedPayload_FailsValidation(t *testing.T) {
	manager := newTestJWTManager(t)
	token, err := manager.GenerateWithPermissions(uuid.New(), "original@example.com", 1, []string{"catalog:read"})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	runes := []rune(parts[1])
	if runes[5] == 'X' {
		runes[5] = 'Y'
	} else {
		runes[5] = 'X'
	}
	tamperedToken := parts[0] + "." + string(runes) + "." + parts[2]

	claims, err := manager.Validate(tamperedToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for tampered token, got: %v", err)
	}
	if claims != nil {
		t.Fatal("expected nil claims on failed validation")
	}
}

func TestJWTManager_ExpiredTokenSignedByWrongKey_ReturnsErrInvalidToken(t *testing.T) {
	manager1 := newTestJWTManager(t)
	manager2 := newTestJWTManager(t)

	past := time.Now().UTC().Add(-20 * time.Minute)
	userID := uuid.New()
	claims := Claims{
		UserID:       userID,
		Email:        "expired-wrongkey@example.com",
		TokenVersion: 0,
		Permissions:  []string{},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "erp-auth",
			Audience:  jwt.ClaimStrings{"erp-api"},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(past),
			NotBefore: jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(10 * time.Minute)),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(manager1.privateKey)
	if err != nil {
		t.Fatal(err)
	}

	gotClaims, err := manager2.Validate(token)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when expired token has invalid signature, got: %v", err)
	}
	if errors.Is(err, ErrExpiredToken) {
		t.Fatal("must not return ErrExpiredToken when signature is invalid")
	}
	if gotClaims != nil {
		t.Fatal("expected nil claims on invalid token signature")
	}
}

func TestJWTManager_FailedValidation_ReturnsNoClaims(t *testing.T) {
	manager := newTestJWTManager(t)

	invalidTokens := []string{
		"",
		"not-a-token",
		"a.b.c",
		"header.payload.signature",
	}

	for _, token := range invalidTokens {
		t.Run("token_"+token, func(t *testing.T) {
			claims, err := manager.Validate(token)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if claims != nil {
				t.Fatalf("expected nil claims on failure, got: %+v", claims)
			}
		})
	}
}

func TestJWTManager_RequiresVersionAndNumericDates(t *testing.T) {
	manager := newTestJWTManager(t)
	id := uuid.NewString()
	now := time.Now().Unix()
	tests := []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"missing version", func(c jwt.MapClaims) { delete(c, "token_version") }},
		{"null version", func(c jwt.MapClaims) { c["token_version"] = nil }},
		{"string version", func(c jwt.MapClaims) { c["token_version"] = "0" }},
		{"fractional version", func(c jwt.MapClaims) { c["token_version"] = 0.5 }},
		{"overflow version", func(c jwt.MapClaims) { c["token_version"] = int64(1) << 32 }},
	}
	for _, field := range []string{"iat", "nbf", "exp"} {
		tests = append(tests, struct {
			name   string
			change func(jwt.MapClaims)
		}{
			"string " + field, func(c jwt.MapClaims) {
				value, err := json.Marshal(c[field])
				if err != nil {
					t.Fatal(err)
				}
				c[field] = string(value)
			},
		})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"user_id": id, "sub": id, "token_version": 0,
				"permissions": []string{}, "iss": "erp-auth", "aud": "erp-api",
				"iat": now, "nbf": now, "exp": now + 900}
			tc.change(claims)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(manager.privateKey)
			if err != nil {
				t.Fatal(err)
			}
			got, err := manager.Validate(raw)
			if !errors.Is(err, ErrInvalidToken) || got != nil {
				t.Fatal("accepted a token outside the shared claim contract")
			}
		})
	}
}

func TestJWTManager_ManagerServiceVerifierContract(t *testing.T) {
	manager := newTestJWTManager(t)

	type ManagerCustomClaims struct {
		jwt.RegisteredClaims
		UserID       string   `json:"user_id"`
		Email        string   `json:"email"`
		TokenVersion *int     `json:"token_version"`
		Permissions  []string `json:"permissions"`
	}

	verifyManagerToken := func(tokenString string) (*ManagerCustomClaims, error) {
		if strings.TrimSpace(tokenString) == "" {
			return nil, errors.New("blank token")
		}
		var claims ManagerCustomClaims
		parsedToken, err := jwt.ParseWithClaims(
			tokenString,
			&claims,
			func(t *jwt.Token) (interface{}, error) {
				if t.Method != jwt.SigningMethodRS256 {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return manager.publicKey, nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithIssuer("erp-auth"),
			jwt.WithAudience("erp-api"),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithNotBeforeRequired(),
			jwt.WithLeeway(0),
		)
		if err != nil || parsedToken == nil || !parsedToken.Valid {
			return nil, errors.New("invalid signature or claims")
		}

		if claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
			return nil, errors.New("missing timestamps")
		}
		if !claims.ExpiresAt.After(claims.IssuedAt.Time) {
			return nil, errors.New("exp not after iat")
		}
		lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
		if lifetime > 15*time.Minute {
			return nil, errors.New("lifetime exceeds 15m")
		}

		if claims.UserID == "" || claims.Subject == "" || claims.UserID != claims.Subject {
			return nil, errors.New("user_id != sub")
		}
		if _, err := uuid.Parse(claims.UserID); err != nil {
			return nil, errors.New("invalid uuid")
		}

		if claims.Email == "" {
			return nil, errors.New("empty email")
		}

		if claims.TokenVersion == nil || *claims.TokenVersion < 0 {
			return nil, errors.New("invalid token version")
		}

		if claims.Permissions == nil || len(claims.Permissions) == 0 {
			return nil, errors.New("empty permissions")
		}
		for _, perm := range claims.Permissions {
			parts := strings.Split(perm, ":")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, errors.New("malformed permission")
			}
		}

		return &claims, nil
	}

	t.Run("admin token with 6 manager permissions satisfies verifier", func(t *testing.T) {
		adminID := uuid.New()
		adminEmail := "admin@erp.local"
		adminPerms := []string{
			"manager.approvals:approve",
			"manager.approvals:read",
			"manager.approvals:reject",
			"manager.approvals:submit",
			"manager.authz:check",
			"manager.rbac:manage",
		}

		tok, err := manager.GenerateWithPermissions(adminID, adminEmail, 1, adminPerms)
		if err != nil {
			t.Fatalf("unexpected token generation error: %v", err)
		}

		claims, err := verifyManagerToken(tok)
		if err != nil {
			t.Fatalf("manager verifier rejected admin token: %v", err)
		}

		if claims.UserID != adminID.String() || claims.Subject != adminID.String() {
			t.Errorf("expected user_id and sub %s, got user_id %s, sub %s", adminID, claims.UserID, claims.Subject)
		}
		if claims.Email != adminEmail {
			t.Errorf("expected email %s, got %s", adminEmail, claims.Email)
		}
		if claims.TokenVersion == nil || *claims.TokenVersion != 1 {
			t.Errorf("expected token_version 1, got %v", claims.TokenVersion)
		}
		if len(claims.Permissions) != 6 {
			t.Errorf("expected 6 permissions, got %d", len(claims.Permissions))
		}
	})

	t.Run("manager token with manager approval permissions satisfies verifier", func(t *testing.T) {
		mgrID := uuid.New()
		mgrEmail := "manager@erp.local"
		mgrPerms := []string{
			"manager.approvals:approve",
			"manager.approvals:read",
			"manager.approvals:reject",
			"manager.approvals:submit",
		}

		tok, err := manager.GenerateWithPermissions(mgrID, mgrEmail, 1, mgrPerms)
		if err != nil {
			t.Fatalf("unexpected token generation error: %v", err)
		}

		claims, err := verifyManagerToken(tok)
		if err != nil {
			t.Fatalf("manager verifier rejected manager token: %v", err)
		}

		if claims.UserID != mgrID.String() || claims.Subject != mgrID.String() {
			t.Errorf("expected user_id and sub %s, got user_id %s, sub %s", mgrID, claims.UserID, claims.Subject)
		}
		if claims.Email != mgrEmail {
			t.Errorf("expected email %s, got %s", mgrEmail, claims.Email)
		}
		if claims.TokenVersion == nil || *claims.TokenVersion != 1 {
			t.Errorf("expected token_version 1, got %v", claims.TokenVersion)
		}
		if len(claims.Permissions) != 4 {
			t.Errorf("expected 4 permissions, got %d", len(claims.Permissions))
		}
	})
}

