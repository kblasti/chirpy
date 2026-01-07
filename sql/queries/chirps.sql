-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetChirps :many
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE user_id != '00000000-0000-0000-0000-000000000000'
ORDER BY created_at ASC;

-- name: GetChirp :one
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE id = $1;

-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE chirps.id = $1 AND user_id = $2;
