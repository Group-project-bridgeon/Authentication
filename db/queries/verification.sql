-- name: UpsertVerification :one
INSERT INTO email_verifications (user_id, otp_hash, attempts, expires_at, last_sent_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (user_id) DO UPDATE
SET otp_hash = EXCLUDED.otp_hash,
    attempts = EXCLUDED.attempts,
    expires_at = EXCLUDED.expires_at,
    last_sent_at = now()
RETURNING *;

-- name: GetVerificationByUserID :one
SELECT * FROM email_verifications WHERE user_id = $1;

-- name: IncrementVerificationAttempts :one
UPDATE email_verifications
SET attempts = attempts + 1
WHERE user_id = $1
RETURNING attempts;

-- name: DeleteVerificationByUserID :exec
DELETE FROM email_verifications WHERE user_id = $1;
