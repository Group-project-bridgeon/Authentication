# Stock Foundation slice 4b — approved machine contract

Status: implemented and verified in disposable infrastructure. User approved these security limits
on 2026-10-23; implementation continued on 2026-10-24.

Auth owns machine UUIDs, enabled state, credentials and explicit grants separately
from users/roles. No identity or grant is seeded. Migration 000007 is additive.
Internal provisioning returns a 32-byte cryptographically random secret once;
only its SHA256 digest is stored. Fast hashing is appropriate for uniformly random
256-bit secrets (not human passwords); comparison is constant time. Credential ID
is a UUID. HTTP Basic username is the machine UUID, password is
`<credential-uuid>.<base64url-secret>`. Credentials expire within 90 days.
Rotation serializes on the machine row: at most two usable credentials, old
credential expiry shortened to at most 24 hours, subsequent rotation retires the
previous overlap. Explicit revocation is immediate for future issuance.

POST /api/v1/auth/service-token accepts only TLS, HTTP Basic and
application/x-www-form-urlencoded with exactly grant_type=client_credentials,
audience=catalog-stock-references and scope=catalog.stock-references:read.
No query parameters, body credentials, duplicate fields or alternative sources.
Maximum body 4096 bytes. Fixed authority must be explicitly granted.
Success: access_token, token_type=Bearer, expires_in; no refresh token.
All responses: Cache-Control: no-store and Pragma: no-cache.
Malformed request 400; invalid client/disabled/expired/revoked/absent grant 401
with generic invalid_client; overload 429; infrastructure failure 503.
Transport requires direct TLS; optional listener TLS certificate/key paths enable
it. Plain HTTP rejects issuance, including spoofed forwarded-proto headers.
This narrow flow is not a complete OAuth authorization server.

RS256 uses existing key-loading conventions. Claims: iss=configured issuer,
aud=[catalog-stock-references], sub=machine:<canonical UUID>, client_id=same UUID,
token_kind=machine, permissions=[catalog.stock-references:read], jti=UUID,
iat=nbf=integer Unix seconds, exp=iat+configured TTL. Default/maximum TTL 300s,
minimum 1s. Catalog tolerance 30s maximum; exp-iat must independently be <=300s.
No user_id, email, human token_version or human refresh workflow.
Strict claim parsing rejects missing/null/malformed/duplicate claims.

Issuance and credential/grant/enable mutations serialize on the same machine row.
Token signing occurs inside that bounded local transaction before release; no
network call is made while locked. A token is released only after commit succeeds.
Disable/revoke/grant removal stops later issuance. Previously issued locally
verified JWTs remain usable until expiry plus 30s; no online revocation is claimed.
Five minutes bounds exposure while allowing brief Auth outages; clocks need NTP.

Internal operations are trusted application interfaces, not public provisioning
routes. No secure operational secret-delivery tooling is provided. Operators must
use an approved secret manager/delivery process before normal provisioning.
No secrets in URLs, logs, fixtures on disk or reports. Endpoint diagnostics use
zerolog component/operation/reason/request_id and SQLSTATE without raw causes.
Process-wide bounded admission avoids spoofable client-IP and unbounded key maps;
multi-instance edge limiting is an operational prerequisite.

Verification: disposable PostgreSQL migration up/down/reapply; real TLS Auth HTTP
issuance to Catalog verifier using temporary in-memory RSA keys; lifecycle races,
rotation, expiry, strict claim and authority failures, human separation, captured
logs, regression tests, deterministic sqlc, formatting/vet/build. No normal
database, machine, grant, key, service or sibling repository changes authorized.

Deployment requires approved backups/migration 000007 before new Auth binary,
TLS configuration and secure operational provisioning. Down deletes machine
metadata and prevents issuance; issued tokens still expire normally. Catalog
verifier is separate; reference route remains unregistered. Slice 4c implements
secured reference transport and Inventory adapter/freshness policy later.

## Operational interface and configuration

MachineService.Create creates a disabled UUID. SetGrant explicitly installs/removes
the single allowed authority, SetEnabled controls issuance, Rotate returns the
credential ID/one-time secret/expiry, and Revoke revokes one credential. These are
trusted internal calls only. Secrets must be handed to approved secure delivery;
do not log returned structs, put them in shell arguments/history or save them in
source. Unknown mutation outcomes require reconciliation by returned ID, not blind
retry. A failed rotation does not disclose its generated secret.

MACHINE_JWT_EXPIRY defaults to 5m and accepts whole seconds from 1s through 5m.
TLS_CERT_PATH and TLS_KEY_PATH must be supplied together to use the TLS listener
(minimum TLS 1.2). Existing plain HTTP startup still works for existing routes;
the new credential endpoint rejects it, including X-Forwarded-Proto spoofing.
No real TLS files or signing keys were created/modified. Proxy TLS termination
without authenticated encrypted transport to this listener is not supported here.

Request fields are grant_type, audience and scope, each exactly once. Example
non-secret body: grant_type=client_credentials&audience=catalog-stock-references&scope=catalog.stock-references%3Aread.
Authorization is Basic with canonical machine UUID and credential-ID.secret as
described above. Successful JSON has access_token (secret), token_type "Bearer"
and numeric expires_in. The Basic credential is never a human password.

The endpoint uses a process-wide bucket of 20 requests with 10 requests/second
refill, and at most eight concurrent operations. This intentionally avoids client
IP/proxy trust assumptions and per-attacker memory growth. It limits one process,
not a distributed deployment; edge capacity controls remain operational work.
Database work is capped at 5s, row-lock waits at 500ms, independent rollback at 2s.
Only the machine endpoint bypasses Gin's URL logger and logs structured safe
reasons through zerolog; existing human logging is not refactored.

## Verification checkpoint

Real disposable PostgreSQL and temporary in-memory keys verified issuance through
the Auth router over TLS into the separate Catalog verifier/middleware. Existing
human verifiers reject the issued machine token. Credential/grant/disabled/expiry
and rotation cases, concurrent rotations, and issuance serialized after disable
passed. The same issued JWT remains verifiable after its credential is revoked.
Captured endpoint/router logs contain none of the generated credentials/tokens.
The cross-module contract uses a temporary compiled Catalog test binary with a
stdin pipe; go test itself does not forward stdin. No tokens/keys are stored in
files. Migration up/down/reapply and no automatic provisioning passed.

Catalog regression tests passed. Auth regression found missing Basic credentials
mapped to 400; corrected to 401 and all focused machine handler/config/service
checks passed. Other Auth packages passed in that regression run. Both projects
passed vet/build; nonfatal module-stat cache permission warnings were observed.
sqlc/sqlc:1.31.1 regeneration produced identical hashes for nine outputs. Seven
unchanged generated files retain their original bytes. Gated integration tests
skip without the explicitly isolated fixture environment; skips are not DB proof.

Slice 4c remains next: approved secured reference transport, actual Inventory
adapter, timeout/body budgets and finalized freshness policy. Normal deployment,
TLS/key distribution, secure provisioning/delivery and multi-instance abuse
controls remain operational prerequisites. No normal machine/grant was provisioned.


## Milestone 8 approved reservation authority extension (2026-10-27)

The earlier fixed-authority sections describe the original Catalog milestone.
Migration 000011 adds the separate exact audience `inventory-reservations` with
only `inventory.reservations:consume`, `inventory.reservations:read`,
`inventory.reservations:release`, `inventory.reservations:reserve`. The user approved
machine-only Inventory reservation access. No human permission definition, automatic
grant or identity is added. Catalog's original audience/single scope remain unchanged.

The same TLS-only Basic endpoint accepts a canonical space-separated sorted unique
subset of these four scopes (at least one); all requested scopes must be explicitly
granted to the verified machine under that audience. Missing, duplicate, unsorted,
unknown or cross-audience scopes reject; there is no all-scope default. Issuance
returns only the requested subset. Example non-secret form values:

```text
grant_type=client_credentials
audience=inventory-reservations
scope=inventory.reservations:read inventory.reservations:release
```

Form-encode those values and supply Basic credentials over verified TLS, never in
the URL/body. The JWT retains separate machine UUID/subject/kind, integer iat=nbf,
maximum issued lifetime 300 seconds, and no human user_id/refresh/token_version.
Inventory verifies exact audience/scope and allows at most 30 seconds clock tolerance,
which does not enlarge the issued lifetime. Existing 256-bit hashed-only credentials,
mandatory <=90-day expiry, <=two usable credentials, <=24-hour overlap and immediate
future-issuance revocation remain unchanged. Already-issued JWTs can remain valid
until expiry plus tolerance; no online grant/credential revocation is claimed.

Internal `SetAuthorityGrant` reuses the same bounded machine-row-lock lifecycle
transaction as issuance and changes only the explicitly requested authority pairs.
The legacy `SetGrant`/operator command remains Catalog-specific; revoking its Catalog
grant preserves reservation grants. No public scoped provisioning endpoint or normal
provisioning is added. Normal lifecycle execution/tooling needs a separate reviewed
plan. Rotating credentials for the same machine preserves Inventory ownership;
replacing a machine identity does not transfer existing holds.

Apply schema 11 before using these new grants; its down migration refuses populated
reservation grants and preserves them transactionally. A failed down may leave a
dirty migrate marker; inspect schema/data and use reviewed forward recovery instead
of deleting grants or forcing a marker without a plan. Disposable verification uses
real Auth issuance into Inventory through HTTPS Kong plus real PostgreSQL lifecycle
services. Synthetic Sales machines exist only in fixtures. See
[Inventory reservation contract](../../Inventory-Service/docs/stock-reservations-spec.md).


## Milestone 9 exact fulfillment authority (2026-10-27)

Auth000012 extends the machine allowlist only with audience inventory-fulfillment:
resource inventory.dispatches, actions create/cancel/read. Canonical full-scope form
is `inventory.dispatches:cancel inventory.dispatches:create inventory.dispatches:read`;
requested scopes may be a sorted unique nonempty subset. Every requested grant is
required. Machine dispatch/update, hyphenated draft aliases and bare resources reject.
Existing TLS Basic/form, hashed expiring credentials, lifetime/rotation/revocation
limits and Catalog/reservation authority remain unchanged. No new endpoint or normal
machine provisioning is introduced. Existing local admin CLI remains Catalog-specific.

Human definitions only: resource inventory.dispatches/action dispatch; resource
inventory.deliveries/action update; resource inventory.dispatches/action read.
The corresponding exact GLOBAL human grants permit cross-owner/warehouse operations
without impersonation. Machine permissions never confer human authority; human
permissions never confer Sales create/cancel. Actual human actor is audited separately
from owner. No users/roles/grants are seeded. Signed human/machine JWTs remain
stateless; renewed tokens reflect revoked grants, with no online-revocation claim.

Empty Auth12 down/reapply is supported; populated fulfillment grants cause refusal.
Permission definitions are retained to protect pre-existing rows/grants. Normal
migration/grant execution needs separate reviewed authorization/backups; no normal
changes ran in this milestone. See [fulfillment contract](../../Inventory-Service/docs/fulfillment-spec.md).
