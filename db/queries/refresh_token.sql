-- =========================================================
-- REFRESH TOKENS
-- =========================================================

-- name: CreateRefreshToken :one
INSERT INTO identity_refresh_tokens (
    user_id,
    family_id,
    token_hash,
    user_agent,
    ip_address,
    expires_at,
    family_expires_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
)
RETURNING *;


-- name: GetRefreshTokenByHash :one
SELECT *
FROM identity_refresh_tokens
WHERE token_hash = $1;


-- name: GetRefreshTokenByID :one
SELECT *
FROM identity_refresh_tokens
WHERE id = $1;


-- name: GetRefreshTokenFamily :many
SELECT *
FROM identity_refresh_tokens
WHERE family_id = $1
ORDER BY created_at ASC;


-- name: RotateRefreshToken :exec
UPDATE identity_refresh_tokens
SET replaced_by_id = $2,
    replaced_at = now(),
    last_used_at = now()
WHERE id = $1;


-- name: RevokeRefreshToken :exec
UPDATE identity_refresh_tokens
SET revoked_at = now(),
    revoked_reason = $2
WHERE id = $1
  AND revoked_at IS NULL;


-- name: RevokeRefreshTokenFamily :exec
UPDATE identity_refresh_tokens
SET revoked_at = now(),
    revoked_reason = $2
WHERE family_id = $1
  AND revoked_at IS NULL;


-- name: UpdateRefreshTokenLastUsed :exec
UPDATE identity_refresh_tokens
SET last_used_at = now()
WHERE id = $1;


-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM identity_refresh_tokens
WHERE expires_at <= now();