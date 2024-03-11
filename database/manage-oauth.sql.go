// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: manage-oauth.sql

package database

import (
	"context"
	"database/sql"
)

const getAppList = `-- name: GetAppList :many
SELECT subject, name, domain, owner, public, sso, active
FROM client_store
WHERE owner = ?
   OR ? = 1
LIMIT 25 OFFSET ?
`

type GetAppListParams struct {
	Owner   string      `json:"owner"`
	Column2 interface{} `json:"column_2"`
	Offset  int64       `json:"offset"`
}

type GetAppListRow struct {
	Subject string        `json:"subject"`
	Name    string        `json:"name"`
	Domain  string        `json:"domain"`
	Owner   string        `json:"owner"`
	Public  sql.NullInt64 `json:"public"`
	Sso     sql.NullInt64 `json:"sso"`
	Active  sql.NullInt64 `json:"active"`
}

func (q *Queries) GetAppList(ctx context.Context, arg GetAppListParams) ([]GetAppListRow, error) {
	rows, err := q.db.QueryContext(ctx, getAppList, arg.Owner, arg.Column2, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAppListRow
	for rows.Next() {
		var i GetAppListRow
		if err := rows.Scan(
			&i.Subject,
			&i.Name,
			&i.Domain,
			&i.Owner,
			&i.Public,
			&i.Sso,
			&i.Active,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getClientInfo = `-- name: GetClientInfo :one
SELECT secret, name, domain, public, sso, active
FROM client_store
WHERE subject = ?
LIMIT 1
`

type GetClientInfoRow struct {
	Secret string        `json:"secret"`
	Name   string        `json:"name"`
	Domain string        `json:"domain"`
	Public sql.NullInt64 `json:"public"`
	Sso    sql.NullInt64 `json:"sso"`
	Active sql.NullInt64 `json:"active"`
}

func (q *Queries) GetClientInfo(ctx context.Context, subject string) (GetClientInfoRow, error) {
	row := q.db.QueryRowContext(ctx, getClientInfo, subject)
	var i GetClientInfoRow
	err := row.Scan(
		&i.Secret,
		&i.Name,
		&i.Domain,
		&i.Public,
		&i.Sso,
		&i.Active,
	)
	return i, err
}

const insertClientApp = `-- name: InsertClientApp :exec
INSERT INTO client_store (subject, name, secret, domain, owner, public, sso, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`

type InsertClientAppParams struct {
	Subject string        `json:"subject"`
	Name    string        `json:"name"`
	Secret  string        `json:"secret"`
	Domain  string        `json:"domain"`
	Owner   string        `json:"owner"`
	Public  sql.NullInt64 `json:"public"`
	Sso     sql.NullInt64 `json:"sso"`
	Active  sql.NullInt64 `json:"active"`
}

func (q *Queries) InsertClientApp(ctx context.Context, arg InsertClientAppParams) error {
	_, err := q.db.ExecContext(ctx, insertClientApp,
		arg.Subject,
		arg.Name,
		arg.Secret,
		arg.Domain,
		arg.Owner,
		arg.Public,
		arg.Sso,
		arg.Active,
	)
	return err
}

const updateClientApp = `-- name: UpdateClientApp :exec
UPDATE client_store
SET name   = ?,
    domain = ?,
    public = ?,
    sso    = ?,
    active = ?
WHERE subject = ?
  AND owner = ?
`

type UpdateClientAppParams struct {
	Name    string        `json:"name"`
	Domain  string        `json:"domain"`
	Public  sql.NullInt64 `json:"public"`
	Sso     sql.NullInt64 `json:"sso"`
	Active  sql.NullInt64 `json:"active"`
	Subject string        `json:"subject"`
	Owner   string        `json:"owner"`
}

func (q *Queries) UpdateClientApp(ctx context.Context, arg UpdateClientAppParams) error {
	_, err := q.db.ExecContext(ctx, updateClientApp,
		arg.Name,
		arg.Domain,
		arg.Public,
		arg.Sso,
		arg.Active,
		arg.Subject,
		arg.Owner,
	)
	return err
}

const resetClientAppSecret = `-- name: resetClientAppSecret :exec
UPDATE client_store
SET secret = ?
WHERE subject = ?
  AND owner = ?
`

type resetClientAppSecretParams struct {
	Secret  string `json:"secret"`
	Subject string `json:"subject"`
	Owner   string `json:"owner"`
}

func (q *Queries) resetClientAppSecret(ctx context.Context, arg resetClientAppSecretParams) error {
	_, err := q.db.ExecContext(ctx, resetClientAppSecret, arg.Secret, arg.Subject, arg.Owner)
	return err
}
