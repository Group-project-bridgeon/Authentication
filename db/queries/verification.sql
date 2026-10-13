-- name: CreateEmailVerificationToken :one
INSERT INTO identity_email_verification_tokens (
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

-- name: GetEmailVerificationTokenByUserID :one
SELECT *
FROM identity_email_verification_tokens
WHERE user_id = $1
  AND verified_at IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetActiveEmailVerificationToken :one
SELECT *
FROM identity_email_verification_tokens
WHERE user_id = $1
  AND verified_at IS NULL
  AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: GetEmailVerificationTokenByHash :one
SELECT *
FROM identity_email_verification_tokens
WHERE token_hash = $1
  AND verified_at IS NULL
  AND expires_at > now();

-- name: IncrementEmailVerificationAttempts :exec
UPDATE identity_email_verification_tokens
SET attempt_count = attempt_count + 1
WHERE id = $1;

-- name: MarkEmailVerificationTokenUsed :exec
UPDATE identity_email_verification_tokens
SET verified_at = now()
WHERE id = $1
  AND verified_at IS NULL;

-- name: DeleteEmailVerificationTokensByUserID :exec
DELETE FROM identity_email_verification_tokens
WHERE user_id = $1;