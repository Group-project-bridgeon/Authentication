-- =========================================================
-- USERS
-- =========================================================

-- name: CreateUser :one
INSERT INTO identity_users (
    email,
    full_name
)
VALUES (
    $1,
    $2
)
RETURNING *;


-- name: GetUserByEmail :one
SELECT *
FROM identity_users
WHERE email = $1;


-- name: GetUserByID :one
SELECT *
FROM identity_users
WHERE id = $1;


-- name: MarkEmailVerified :exec
UPDATE identity_users
SET email_verified_at = now(),
    updated_at = now()
WHERE id = $1;


-- =========================================================
-- CREDENTIALS
-- =========================================================

-- name: CreateCredentials :one
INSERT INTO identity_credentials (
    user_id,
    password_hash,
    password_changed_at
)
VALUES (
    $1,
    $2,
    now()
)
RETURNING *;


-- name: GetCredentialsByUserID :one
SELECT *
FROM identity_credentials
WHERE user_id = $1;


-- name: UpdatePassword :exec
INSERT INTO identity_credentials (
    user_id,
    password_hash,
    password_changed_at,
    failed_login_count,
    locked_until,
    updated_at
)
VALUES (
    $1,
    $2,
    now(),
    0,
    NULL,
    now()
)
ON CONFLICT (user_id) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    password_changed_at = now(),
    failed_login_count = 0,
    locked_until = NULL,
    updated_at = now();


-- =========================================================
-- EXTERNAL IDENTITIES / OAUTH
-- =========================================================

-- name: CreateExternalIdentity :one
INSERT INTO identity_external_identities (
    user_id,
    provider,
    provider_subject,
    email_at_link
)
VALUES (
    $1,
    $2,
    $3,
    $4
)
RETURNING *;


-- name: GetUserByExternalIdentity :one
SELECT u.*
FROM identity_users AS u
INNER JOIN identity_external_identities AS e
    ON e.user_id = u.id
WHERE e.provider = $1
  AND e.provider_subject = $2;

-- name: IncrementTokenVersion :one
UPDATE identity_users
SET token_version = token_version + 1,
    updated_at = now()
WHERE id = $1
RETURNING token_version;
