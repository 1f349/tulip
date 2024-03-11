-- name: HasUser :one
SELECT cast(count(subject) AS BOOLEAN) AS hasUser
FROM users;

-- name: addUser :exec
INSERT INTO users (subject, name, username, password, email, email_verified, role, updated_at, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: checkLogin :one
SELECT subject, password, EXISTS(SELECT 1 FROM otp WHERE otp.subject = users.subject), email, email_verified
FROM users
WHERE username = ?
LIMIT 1;

-- name: GetUser :one
SELECT *
FROM users
WHERE subject = ?
LIMIT 1;

-- name: GetUserRole :one
SELECT role
FROM users
WHERE subject = ?;

-- name: GetUserDisplayName :one
SELECT name
FROM users
WHERE subject = ?;

-- name: getUserPassword :one
SELECT password
FROM users
WHERE subject = ?;

-- name: changeUserPassword :execrows
UPDATE users
SET password   = ?,
    updated_at = ?
WHERE subject = ?
  AND password = ?;

-- name: ModifyUser :execrows
UPDATE users
SET name      = ?,
    picture   = ?,
    website=?,
    pronouns=?,
    birthdate=?,
    zoneinfo=?,
    locale=?,
    updated_at=?
WHERE subject = ?;

-- name: SetTwoFactor :exec
INSERT OR
REPLACE
INTO otp (subject, secret, digits)
VALUES (?, ?, ?);

-- name: DeleteTwoFactor :exec
DELETE
FROM otp
WHERE otp.subject = ?;

-- name: GetTwoFactor :one
SELECT secret, digits
FROM otp
WHERE subject = ?;

-- name: HasTwoFactor :one
SELECT cast(EXISTS(SELECT 1 FROM otp WHERE subject = ?) AS BOOLEAN);
