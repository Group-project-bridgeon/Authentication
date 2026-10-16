package helper

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const MaxAccessTokenLifetime = 15 * time.Minute

var (
	ErrInvalidToken        = errors.New("invalid or malformed token")
	ErrExpiredToken        = errors.New("token has expired")
	ErrMalformedPermission = errors.New("malformed permission")
)

type Claims struct {
	UserID       uuid.UUID `json:"user_id"`
	Email        string    `json:"email"`
	TokenVersion int32     `json:"token_version"`

	// Permissions contains GLOBAL grants only.
	Permissions []string `json:"permissions"`

	jwt.RegisteredClaims
}

// Keep the decoded contract consistent with Catalog: absent/null versions must
// not silently become zero, and NumericDate claims must be JSON numbers.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type plainClaims Claims
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var version *int32
	if err := json.Unmarshal(fields["token_version"], &version); err != nil || version == nil {
		return ErrInvalidToken
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		var number any
		if err := json.Unmarshal(fields[name], &number); err != nil {
			return ErrInvalidToken
		}
		if _, ok := number.(float64); !ok {
			return ErrInvalidToken
		}
	}
	return json.Unmarshal(data, (*plainClaims)(c))
}

// Validate adds application-specific checks to jwt/v5 validation.
// Standard signature, expiry, issuer and audience checks are configured
// separately in JWTManager.Validate.
func (c Claims) Validate() error {
	if c.UserID == uuid.Nil || c.Subject != c.UserID.String() {
		return ErrInvalidToken
	}
	if c.TokenVersion < 0 {
		return ErrInvalidToken
	}
	if c.Permissions == nil {
		return ErrInvalidToken
	}
	for _, permission := range c.Permissions {
		if err := ValidatePermissionString(permission); err != nil {
			return ErrInvalidToken
		}
	}

	if c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil {
		return ErrInvalidToken
	}

	iat := c.IssuedAt.Time
	nbf := c.NotBefore.Time
	exp := c.ExpiresAt.Time

	if !exp.After(iat) || nbf.Before(iat) || !exp.After(nbf) {
		return ErrInvalidToken
	}
	if exp.Sub(iat) > MaxAccessTokenLifetime {
		return ErrInvalidToken
	}

	return nil
}

type JWTManager struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	issuer        string
	audience      string
	tokenDuration time.Duration
}

func NewJWTManager(
	key *rsa.PrivateKey,
	issuer string,
	audience string,
	duration time.Duration,
) (*JWTManager, error) {
	if err := validateRSAKey(key); err != nil {
		return nil, err
	}

	if strings.TrimSpace(issuer) == "" ||
		issuer != strings.TrimSpace(issuer) {
		return nil, errors.New("JWT issuer must be nonblank without surrounding whitespace")
	}
	if strings.TrimSpace(audience) == "" ||
		audience != strings.TrimSpace(audience) {
		return nil, errors.New("JWT audience must be nonblank without surrounding whitespace")
	}
	if duration < time.Second || duration > MaxAccessTokenLifetime {
		return nil, errors.New("JWT lifetime must be between 1s and 15m")
	}

	return &JWTManager{
		privateKey:    key,
		publicKey:     &key.PublicKey,
		issuer:        issuer,
		audience:      audience,
		tokenDuration: duration,
	}, nil
}

func (m *JWTManager) Duration() time.Duration {
	return m.tokenDuration
}

func FormatPermission(resource, action string) (string, error) {
	if resource == "" || action == "" {
		return "", ErrMalformedPermission
	}
	if resource != strings.TrimSpace(resource) ||
		action != strings.TrimSpace(action) {
		return "", ErrMalformedPermission
	}
	if strings.Contains(resource, ":") || strings.Contains(action, ":") {
		return "", ErrMalformedPermission
	}
	return resource + ":" + action, nil
}

func ValidatePermissionString(permission string) error {
	parts := strings.Split(permission, ":")
	if len(parts) != 2 {
		return ErrMalformedPermission
	}
	_, err := FormatPermission(parts[0], parts[1])
	return err
}

func (m *JWTManager) Generate(userID uuid.UUID, email string) (string, error) {
	return m.GenerateWithPermissions(userID, email, 0, nil)
}

func (m *JWTManager) GenerateVersioned(
	userID uuid.UUID,
	email string,
	version int32,
) (string, error) {
	return m.GenerateWithPermissions(userID, email, version, nil)
}

func (m *JWTManager) GenerateWithPermissions(
	userID uuid.UUID,
	email string,
	version int32,
	permissions []string,
) (string, error) {
	if userID == uuid.Nil || version < 0 {
		return "", ErrInvalidToken
	}

	grants := make([]string, 0, len(permissions))
	seen := make(map[string]struct{}, len(permissions))

	for _, permission := range permissions {
		if err := ValidatePermissionString(permission); err != nil {
			return "", err
		}
		if _, exists := seen[permission]; !exists {
			seen[permission] = struct{}{}
			grants = append(grants, permission)
		}
	}
	sort.Strings(grants)

	now := time.Now().UTC()
	claims := Claims{
		UserID:       userID,
		Email:        email,
		TokenVersion: version,
		Permissions:  grants,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.tokenDuration)),
		},
	}

	if err := claims.Validate(); err != nil {
		return "", err
	}

	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).
		SignedString(m.privateKey)
}

func (m *JWTManager) Validate(raw string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		raw,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, ErrInvalidToken
			}
			return m.publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithIssuedAt(),
	)

	if err != nil {
		// Never describe a token with an invalid signature as merely expired.
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
