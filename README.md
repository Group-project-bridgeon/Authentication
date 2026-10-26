# Authentication Service

The Authentication Service handles user registration, credentials, email verification, password reset, OAuth 2.0 (Google), and JWT access token issuance for the ERP platform.

---

## JWT Architecture & Configuration

The service signs JWT access tokens using asymmetric **RS256** (RSA Signature with SHA-256).

### Key Architecture
- **Asymmetric Signing**: The Authentication service holds the private key and signs access tokens. Downstream services (such as Catalog) receive only the corresponding RSA public key for verification.
- **Startup Loading**: The RSA private key (`PKCS#1` or `PKCS#8` PEM, minimum 2048 bits) is loaded and validated once at application startup.
- **Global Permissions Claim**: Issued tokens include a `permissions` claim containing only validated, deduplicated, and sorted **GLOBAL** role grants formatted as `resource:action`. Scoped grants (e.g. warehouse-scoped or tenant-scoped roles) are excluded from this claim.
- **Strict Token Lifetime**: Access tokens have a maximum lifetime of 15 minutes (`MaxAccessTokenLifetime`), strictly enforced with no validation leeway. Token timestamps must be JSON numbers satisfying `exp > iat`, `nbf >= iat`, `exp > nbf`, and `exp - iat <= 15m`. Missing/null `token_version` is rejected; explicit version zero is valid.
- **Legacy HS256 Cutover**: Existing symmetric HS256 tokens are not accepted by RS256 validators. Users with older tokens must re-authenticate to obtain RS256 tokens.
- **Revocation Model**: Downstream services performing local stateless JWT verification validate cryptographic signatures and expiration locally. Local verification does not provide immediate revocation upon database `token_version` bumps until the token expires (maximum 15 minutes).

### Required Environment Variables

| Variable | Description | Example |
|---|---|---|
| `JWT_PRIVATE_KEY_PATH` | Path to the RSA private key PEM file (PKCS#1 or PKCS#8, $\ge$ 2048 bits) | `./keys/jwt-private.pem` |
| `JWT_ISSUER` | Token issuer identifier (nonblank, no surrounding whitespace) | `erp-auth` |
| `JWT_AUDIENCE` | Token audience identifier (nonblank, no surrounding whitespace) | `erp-api` |
| `JWT_EXPIRY` | Token validity duration ($1\text{s} \le \text{duration} \le 15\text{m}$) | `15m` |

### Key Management
Private keys must reside in the ignored `/keys/` directory and must **never** be committed to version control or copied into container images (`.gitignore` and `.dockerignore` ignore `/keys/`).

To generate local development keys:
```bash
# Generate 2048-bit RSA private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ./keys/jwt-private.pem

# Export public key for downstream services
openssl pkey -in ./keys/jwt-private.pem -pubout -out ./keys/jwt-public.pem
```

---

## Catalog Integration

- **Cross-Service Key Mounts**: ERP-Platform mounts the public key read-only into Catalog; only Auth receives the private key.
- **Catalog Protection**: Catalog verifies RS256 locally and enforces exact GLOBAL resource permissions. Migration 000005 defines grants without assigning users. See [Catalog security](../Catalog-Service/docs/security.md) and [isolated verification](../ERP-Platform/docs/catalog-security-verification.md). The user reported the isolated Docker/Kong suite passing with exit 0. This is user-reported runtime evidence, separate from agent-run unit checks; see the Platform verification record for scope and limitations.

---

The Auth, Catalog and Platform changes require a coordinated rollout with matching RSA keys, issuer/audience, and migration 000005. Old Auth configuration or missing Catalog public-key configuration can break startup or access. Permission assignments require fresh login; Catalog may accept existing tokens until expiry, up to 15 minutes.

## Running Tests

Run all unit tests:
```bash
go test -count=1 ./...
```

Run focused helper and configuration tests:
```bash
go test -count=1 ./internal/helper ./internal/config
```

Run service and middleware tests:
```bash
go test -count=1 ./internal/service ./internal/middleware ./internal/router
```

Run PostgreSQL integration tests (requires a running PostgreSQL instance and `TEST_DATABASE_URL`):
```bash
go test -v -count=1 ./internal/repository/postgres
```
*(When `TEST_DATABASE_URL` is unset, PostgreSQL integration tests are safely skipped).*