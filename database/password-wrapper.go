package database

import (
	"context"
	"github.com/1f349/tulip/database/types"
	"github.com/1f349/tulip/password"
	"github.com/google/uuid"
	"time"
)

type AddUserParams struct {
	Name          string         `json:"name"`
	Username      string         `json:"username"`
	Password      string         `json:"password"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Role          types.UserRole `json:"role"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Active        bool           `json:"active"`
}

func (q *Queries) AddUser(ctx context.Context, arg AddUserParams) (string, error) {
	pwHash, err := password.HashPassword(arg.Password)
	if err != nil {
		return "", err
	}
	a := addUserParams{
		Subject:       uuid.NewString(),
		Name:          arg.Name,
		Username:      arg.Username,
		Password:      pwHash,
		Email:         arg.Email,
		EmailVerified: arg.EmailVerified,
		Role:          arg.Role,
		UpdatedAt:     arg.UpdatedAt,
		Active:        arg.Active,
	}
	return a.Subject, q.addUser(ctx, a)
}

type CheckLoginRow struct {
	Subject       string              `json:"subject"`
	Password      password.HashString `json:"password"`
	HasTwoFactor  bool                `json:"hasTwoFactor"`
	Email         string              `json:"email"`
	EmailVerified bool                `json:"email_verified"`
}
