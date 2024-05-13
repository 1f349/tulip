-- name: GetUserList :many
SELECT subject,
       name,
       username,
       picture,
       website,
       email,
       email_verified,
       role,
       updated_at,
       active
FROM users
LIMIT 25 OFFSET ?;

-- name: UpdateUserRole :exec
UPDATE users
SET active = ?,
    role=?
WHERE subject = ?;

-- name: VerifyUserEmail :exec
UPDATE users
SET email_verified = 1
WHERE subject = ?;

-- name: UserEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND email_verified = 1) == 1 AS email_exists;
