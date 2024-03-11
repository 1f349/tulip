-- name: GetClientInfo :one
SELECT *
FROM client_store
WHERE subject = ?
LIMIT 1;

-- name: GetAppList :many
SELECT subject, name, domain, owner, public, sso, active
FROM client_store
WHERE owner = ?
   OR ? = 1
LIMIT 25 OFFSET ?;

-- name: InsertClientApp :exec
INSERT INTO client_store (subject, name, secret, domain, owner, public, sso, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateClientApp :exec
UPDATE client_store
SET name   = ?,
    domain = ?,
    public = ?,
    sso    = ?,
    active = ?
WHERE subject = ?
  AND owner = ?;

-- name: resetClientAppSecret :exec
UPDATE client_store
SET secret = ?
WHERE subject = ?
  AND owner = ?;
