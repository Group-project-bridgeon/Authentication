-- =========================================================
-- AUTHENTICATION EVENTS
-- =========================================================

-- name: CreateAuthEvent :one
INSERT INTO identity_auth_events (
    user_id,
    email_attempted,
    event_type,
    ip_address,
    user_agent,
    request_id
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
RETURNING *;


-- name: GetAuthEventByID :one
SELECT *
FROM identity_auth_events
WHERE id = $1;


-- name: GetUserAuthEvents :many
SELECT *
FROM identity_auth_events
WHERE user_id = $1
ORDER BY created_at DESC;


-- name: GetAuthEventsByType :many
SELECT *
FROM identity_auth_events
WHERE event_type = $1
ORDER BY created_at DESC;


-- name: GetRecentAuthEvents :many
SELECT *
FROM identity_auth_events
ORDER BY created_at DESC
LIMIT $1;


-- name: DeleteOldAuthEvents :exec
DELETE FROM identity_auth_events
WHERE created_at < $1;