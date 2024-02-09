package database

import (
	"database/sql"
	"fmt"
	"github.com/1f349/tulip/password"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"time"
)

func updatedAt() string {
	return time.Now().UTC().Format(time.DateTime)
}

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

func (t *Tx) InsertUser(name, un, pw, email string, verifyEmail bool, role UserRole, active bool) (uuid.UUID, error) {
	pwHash, err := password.HashPassword(pw)
	if err != nil {
		return uuid.UUID{}, err
	}
	u := uuid.New()
	_, err = t.tx.Exec(`INSERT INTO users (subject, name, username, password, email, email_verified, role, updated_at, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, u, name, un, pwHash, email, verifyEmail, role, updatedAt(), active)
	return u, err
}

func (t *Tx) CheckLogin(un, pw string) (*User, bool, bool, error) {
	var u User
	var pwHash password.HashString
	var hasOtp, hasVerify bool
	row := t.tx.QueryRow(`SELECT subject, password, EXISTS(SELECT 1 FROM otp WHERE otp.subject = users.subject), email, email_verified FROM users WHERE username = ?`, un)
	err := row.Scan(&u.Sub, &pwHash, &hasOtp, &u.Email, &hasVerify)
	if err != nil {
		return nil, false, false, err
	}
	err = password.CheckPasswordHash(pwHash, pw)
	return &u, hasOtp, hasVerify, err
}

func (t *Tx) GetUserDisplayName(sub string) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name FROM users WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&u.Name)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUserRole(sub string) (UserRole, error) {
	var r UserRole
	row := t.tx.QueryRow(`SELECT role FROM users WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&r)
	return r, err
}

func (t *Tx) GetUser(sub string) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name, username, picture, website, email, email_verified, pronouns, birthdate, zoneinfo, locale, updated_at, active FROM users WHERE subject = ?`, sub)
	err := row.Scan(&u.Name, &u.Username, &u.Picture, &u.Website, &u.Email, &u.EmailVerified, &u.Pronouns, &u.Birthdate, &u.ZoneInfo, &u.Locale, &u.UpdatedAt, &u.Active)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUserEmail(sub string) (string, error) {
	var email string
	row := t.tx.QueryRow(`SELECT email FROM users WHERE subject = ?`, sub)
	err := row.Scan(&email)
	return email, err
}

func (t *Tx) ChangeUserPassword(sub, pwOld, pwNew string) error {
	q, err := t.tx.Query(`SELECT password FROM users WHERE subject = ?`, sub)
	if err != nil {
		return err
	}
	var pwHash password.HashString
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
	exec, err := t.tx.Exec(`UPDATE users SET password = ?, updated_at = ? WHERE subject = ? AND password = ?`, pwNewHash, updatedAt(), sub, pwHash)
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

func (t *Tx) ModifyUser(sub string, v *UserPatch) error {
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
		updatedAt(),
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

func (t *Tx) SetTwoFactor(sub string, secret string, digits int) error {
	if secret == "" && digits == 0 {
		_, err := t.tx.Exec(`DELETE FROM otp WHERE otp.subject = ?`, sub)
		return err
	}
	_, err := t.tx.Exec(`INSERT INTO otp(subject, secret, digits) VALUES (?, ?, ?) ON CONFLICT(subject) DO UPDATE SET secret = excluded.secret, digits = excluded.digits`, sub, secret, digits)
	return err
}

func (t *Tx) GetTwoFactor(sub string) (string, int, error) {
	var secret string
	var digits int
	row := t.tx.QueryRow(`SELECT secret, digits FROM otp WHERE subject = ?`, sub)
	err := row.Scan(&secret, &digits)
	if err != nil {
		return "", 0, err
	}
	return secret, digits, nil
}

func (t *Tx) HasTwoFactor(sub string) (bool, error) {
	var hasOtp bool
	row := t.tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM otp WHERE otp.subject = ?)`, sub)
	err := row.Scan(&hasOtp)
	if err != nil {
		return false, err
	}
	return hasOtp, row.Err()
}

func (t *Tx) GetClientInfo(sub string) (oauth2.ClientInfo, error) {
	var u ClientInfoDbOutput
	row := t.tx.QueryRow(`SELECT secret, name, domain, public, sso, active FROM client_store WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&u.Secret, &u.Name, &u.Domain, &u.Public, &u.SSO, &u.Active)
	u.Owner = sub
	if !u.Active {
		return nil, fmt.Errorf("client is not active")
	}
	return &u, err
}

func (t *Tx) GetAppList(owner string, admin bool, offset int) ([]ClientInfoDbOutput, error) {
	var u []ClientInfoDbOutput
	row, err := t.tx.Query(`SELECT subject, name, domain, owner, public, sso, active FROM client_store WHERE owner = ? OR ? = 1 LIMIT 25 OFFSET ?`, owner, admin, offset)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		var a ClientInfoDbOutput
		err := row.Scan(&a.Sub, &a.Name, &a.Domain, &a.Owner, &a.Public, &a.SSO, &a.Active)
		if err != nil {
			return nil, err
		}
		u = append(u, a)
	}
	return u, row.Err()
}

func (t *Tx) InsertClientApp(name, domain string, public, sso, active bool, owner string) error {
	u := uuid.New()
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`INSERT INTO client_store (subject, name, secret, domain, owner, public, sso, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, u.String(), name, secret, domain, owner, public, sso, active)
	return err
}

func (t *Tx) UpdateClientApp(subject, owner string, name, domain string, public, sso, active bool) error {
	_, err := t.tx.Exec(`UPDATE client_store SET name = ?, domain = ?, public = ?, sso = ?, active = ? WHERE subject = ? AND owner = ?`, name, domain, public, sso, active, subject, owner)
	return err
}

func (t *Tx) ResetClientAppSecret(subject, owner string) (string, error) {
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return "", err
	}
	_, err = t.tx.Exec(`UPDATE client_store SET secret = ? WHERE subject = ? AND owner = ?`, secret, subject, owner)
	return secret, err
}

func (t *Tx) GetUserList(offset int) ([]User, error) {
	var u []User
	row, err := t.tx.Query(`SELECT subject, name, username, picture, website, email, email_verified, pronouns, birthdate, zoneinfo, locale, role, updated_at, active FROM users LIMIT 25 OFFSET ?`, offset)
	if err != nil {
		return nil, err
	}
	for row.Next() {
		var a User
		err := row.Scan(&a.Sub, &a.Name, &a.Username, &a.Picture, &a.Website, &a.Email, &a.EmailVerified, &a.Pronouns, &a.Birthdate, &a.ZoneInfo, &a.Locale, &a.Role, &a.UpdatedAt, &a.Active)
		if err != nil {
			return nil, err
		}
		u = append(u, a)
	}
	return u, row.Err()
}

func (t *Tx) UpdateUser(subject string, role UserRole, active bool) error {
	_, err := t.tx.Exec(`UPDATE users SET active = ?, role = ? WHERE subject = ?`, active, role, subject)
	return err
}

func (t *Tx) VerifyUserEmail(sub string) error {
	_, err := t.tx.Exec(`UPDATE users SET email_verified = 1 WHERE subject = ?`, sub)
	return err
}

func (t *Tx) UserResetPassword(sub string, pw string) error {
	hashPassword, err := password.HashPassword(pw)
	if err != nil {
		return err
	}
	exec, err := t.tx.Exec(`UPDATE users SET password = ?, updated_at = ? WHERE subject = ?`, hashPassword, updatedAt(), sub)
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

func (t *Tx) UserEmailExists(email string) (exists bool, err error) {
	row := t.tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? and email_verified = 1)`, email)
	err = row.Scan(&exists)
	return
}
