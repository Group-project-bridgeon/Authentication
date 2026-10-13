-- =========================================================
-- PASSWORD RESET TOKENS
-- =========================================================

-- name: CreatePasswordResetToken :one
INSERT INTO identity_password_reset_tokens (
    user_id,
    token_hash,
    expires_at
)
VALUES (
    $1,
    $2,
    $3
)
RETURNING *;


-- name: GetPasswordResetTokenByHash :one
SELECT *
FROM identity_password_reset_tokens
WHERE token_hash = $1
  AND used_at IS NULL
  AND expires_at > now();


-- name: GetPasswordResetTokenByUserID :one
SELECT *
FROM identity_password_reset_tokens
WHERE user_id = $1
  AND used_at IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetActivePasswordResetToken :one
SELECT *
FROM identity_password_reset_tokens
WHERE user_id = $1
  AND used_at IS NULL
  AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: IncrementPasswordResetAttempts :exec
UPDATE identity_password_reset_tokens
SET attempt_count = attempt_count + 1
WHERE id = $1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE identity_password_reset_tokens
SET used_at = now()
WHERE id = $1
  AND used_at IS NULL;


-- name: DeletePasswordResetTokensByUserID :exec
DELETE FROM identity_password_reset_tokens
WHERE user_id = $1;