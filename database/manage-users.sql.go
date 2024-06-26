// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: manage-users.sql

package database

import (
	"context"
	"time"

	"github.com/1f349/tulip/database/types"
)

const getUserList = `-- name: GetUserList :many
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
LIMIT 25 OFFSET ?
`

type GetUserListRow struct {
	Subject       string         `json:"subject"`
	Name          string         `json:"name"`
	Username      string         `json:"username"`
	Picture       string         `json:"picture"`
	Website       string         `json:"website"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Role          types.UserRole `json:"role"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Active        bool           `json:"active"`
}

func (q *Queries) GetUserList(ctx context.Context, offset int64) ([]GetUserListRow, error) {
	rows, err := q.db.QueryContext(ctx, getUserList, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetUserListRow
	for rows.Next() {
		var i GetUserListRow
		if err := rows.Scan(
			&i.Subject,
			&i.Name,
			&i.Username,
			&i.Picture,
			&i.Website,
			&i.Email,
			&i.EmailVerified,
			&i.Role,
			&i.UpdatedAt,
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

const updateUserRole = `-- name: UpdateUserRole :exec
UPDATE users
SET active = ?,
    role=?
WHERE subject = ?
`

type UpdateUserRoleParams struct {
	Active  bool           `json:"active"`
	Role    types.UserRole `json:"role"`
	Subject string         `json:"subject"`
}

func (q *Queries) UpdateUserRole(ctx context.Context, arg UpdateUserRoleParams) error {
	_, err := q.db.ExecContext(ctx, updateUserRole, arg.Active, arg.Role, arg.Subject)
	return err
}

const userEmailExists = `-- name: UserEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND email_verified = 1) == 1 AS email_exists
`

func (q *Queries) UserEmailExists(ctx context.Context, email string) (bool, error) {
	row := q.db.QueryRowContext(ctx, userEmailExists, email)
	var email_exists bool
	err := row.Scan(&email_exists)
	return email_exists, err
}

const verifyUserEmail = `-- name: VerifyUserEmail :exec
UPDATE users
SET email_verified = 1
WHERE subject = ?
`

func (q *Queries) VerifyUserEmail(ctx context.Context, subject string) error {
	_, err := q.db.ExecContext(ctx, verifyUserEmail, subject)
	return err
}
