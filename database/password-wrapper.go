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

type CheckLoginResult struct {
	Subject       string `json:"subject"`
	Name          string `json:"name"`
	HasOtp        bool   `json:"hasTwoFactor"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (q *Queries) CheckLogin(ctx context.Context, un, pw string) (CheckLoginResult, error) {
	login, err := q.checkLogin(ctx, un)
	if err != nil {
		return CheckLoginResult{}, err
	}
	err = password.CheckPasswordHash(login.Password, pw)
	if err != nil {
		return CheckLoginResult{}, err
	}
	return CheckLoginResult{
		Subject:       login.Subject,
		Name:          login.Name,
		HasOtp:        login.HasOtp,
		Email:         login.Email,
		EmailVerified: login.EmailVerified,
	}, nil
}

func (q *Queries) ChangePassword(ctx context.Context, subject, newPw string) error {
	userPassword, err := q.getUserPassword(ctx, subject)
	if err != nil {
		return err
	}
	newPwHash, err := password.HashPassword(newPw)
	if err != nil {
		return err
	}
	return q.changeUserPassword(ctx, changeUserPasswordParams{
		Password:   newPwHash,
		UpdatedAt:  time.Now(),
		Subject:    subject,
		Password_2: userPassword,
	})
}
