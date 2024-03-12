-- name: HasUser :one
SELECT CAST(count(subject) AS BOOLEAN) AS hasUser
FROM users;

-- name: addUser :exec
INSERT INTO users (subject, name, username, password, email, email_verified, role, updated_at, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: checkLogin :one
SELECT subject, name, password, CAST(EXISTS(SELECT 1 FROM otp WHERE otp.subject = users.subject) AS BOOLEAN) AS has_otp, email, email_verified
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

-- name: changeUserPassword :exec
UPDATE users
SET password   = ?,
    updated_at = ?
WHERE subject = ?
  AND password = ?;

-- name: ModifyUser :exec
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

-- name: SetOtp :exec
INSERT OR
REPLACE
INTO otp (subject, secret, digits)
VALUES (?, ?, ?);

-- name: DeleteOtp :exec
DELETE
FROM otp
WHERE otp.subject = ?;

-- name: GetOtp :one
SELECT secret, digits
FROM otp
WHERE subject = ?;

-- name: HasOtp :one
SELECT CAST(EXISTS(SELECT 1 FROM otp WHERE subject = ?) AS BOOLEAN);

-- name: GetUserEmail :one
SELECT email
FROM users
WHERE subject = ?;
