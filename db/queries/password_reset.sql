-- name: UpsertPasswordReset :one
INSERT INTO password_resets (user_id, otp_hash, attempts, expires_at, last_sent_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (user_id) DO UPDATE
SET otp_hash = EXCLUDED.otp_hash,
    attempts = EXCLUDED.attempts,
    expires_at = EXCLUDED.expires_at,
    last_sent_at = now()
RETURNING *;

-- name: GetPasswordResetByUserID :one
SELECT * FROM password_resets WHERE user_id = $1;

-- name: IncrementPasswordResetAttempts :one
UPDATE password_resets
SET attempts = attempts + 1
WHERE user_id = $1
RETURNING attempts;

-- name: DeletePasswordResetByUserID :exec
DELETE FROM password_resets WHERE user_id = $1;
