package database

import (
	"database/sql"
	"fmt"
	"github.com/1f349/tulip/password"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"time"
)

type Tx struct{ tx *sql.Tx }

func (t *Tx) Commit() error {
	return t.tx.Commit()
}

func (t *Tx) Rollback() {
	_ = t.tx.Rollback()
}

func (t *Tx) HasUser() error {
	var exists bool
	row := t.tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users)`)
	err := row.Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	return nil
}

func (t *Tx) InsertUser(name, un, pw, email string) error {
	pwHash, err := password.HashPassword(pw)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`INSERT INTO users (subject, name, username, password, email) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), name, un, pwHash, email)
	return err
}

func (t *Tx) CheckLogin(un, pw string) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT subject, password FROM users WHERE username = ? LIMIT 1`, un)
	err := row.Scan(&u.Sub, &u.Password)
	if err != nil {
		return nil, err
	}
	err = password.CheckPasswordHash(u.Password, pw)
	return &u, err
}

func (t *Tx) GetUserDisplayName(sub uuid.UUID) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name FROM users WHERE subject = ? LIMIT 1`, sub.String())
	err := row.Scan(&u.Name)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUser(sub uuid.UUID) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name, username, password, picture, website, email, email_verified, pronouns, birthdate, zoneinfo, locale, updated_at, active FROM users WHERE subject = ? LIMIT 1`, sub.String())
	err := row.Scan(&u.Name, &u.Username, &u.Password, &u.Picture, &u.Website, &u.Email, &u.EmailVerified, &u.Pronouns, &u.Birthdate, &u.ZoneInfo, &u.Locale, &u.UpdatedAt, &u.Active)
	u.Sub = sub
	return &u, err
}

func (t *Tx) ChangeUserPassword(sub uuid.UUID, pwOld, pwNew string) error {
	q, err := t.tx.Query(`SELECT password FROM users WHERE subject = ?`, sub)
	if err != nil {
		return err
	}
	var pwHash string
	if q.Next() {
		err = q.Scan(&pwHash)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("invalid user")
	}
	if err := q.Err(); err != nil {
		return err
	}
	if err := q.Close(); err != nil {
		return err
	}
	err = password.CheckPasswordHash(pwHash, pwOld)
	if err != nil {
		return err
	}
	pwNewHash, err := password.HashPassword(pwNew)
	if err != nil {
		return err
	}
	exec, err := t.tx.Exec(`UPDATE users SET password = ?, updated_at = ? WHERE subject = ? AND password = ?`, pwNewHash, time.Now().Format(time.DateTime), sub, pwHash)
	if err != nil {
		return err
	}
	affected, err := exec.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("row wasn't updated")
	}
	return nil
}

func (t *Tx) ModifyUser(sub uuid.UUID, v *UserPatch) error {
	exec, err := t.tx.Exec(
		`UPDATE users
SET name       = ?,
    picture    = ?,
    website    = ?,
    pronouns   = ?,
    birthdate  = ?,
    zoneinfo   = ?,
    locale     = ?,
    updated_at = ?
WHERE subject = ?`,
		v.Name,
		v.Picture,
		v.Website,
		v.Pronouns.String(),
		v.Birthdate,
		v.ZoneInfo.String(),
		v.Locale.String(),
		time.Now().Format(time.DateTime),
		sub,
	)
	if err != nil {
		return err
	}
	affected, err := exec.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("row wasn't updated")
	}
	return nil
}

func (t *Tx) GetClientInfo(sub string) (oauth2.ClientInfo, error) {
	var u clientInfoDbOutput
	row := t.tx.QueryRow(`SELECT secret, domain, sso, active FROM client_store WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&u.secret, &u.domain, &u.sso)
	u.sub = sub
	return &u, err
}

type clientInfoDbOutput struct {
	sub, secret, domain string
	sso                 bool
}

func (c *clientInfoDbOutput) GetID() string     { return c.sub }
func (c *clientInfoDbOutput) GetSecret() string { return c.secret }
func (c *clientInfoDbOutput) GetDomain() string { return c.domain }
func (c *clientInfoDbOutput) IsPublic() bool    { return false }
func (c *clientInfoDbOutput) GetUserID() string { return "" }
func (c *clientInfoDbOutput) IsSSO() bool       { return c.sso }
