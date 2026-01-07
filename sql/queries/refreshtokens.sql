-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days',
    NULL
)
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT users.id, users.created_at, users.updated_at, users.email, users.is_chirpy_red FROM refresh_tokens
INNER JOIN users ON refresh_tokens.user_id = users.id
WHERE token = $1
AND revoked_at IS NULL
AND NOW() < expires_at;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;
