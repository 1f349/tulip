package database

import (
	"database/sql"
	"fmt"
	"github.com/1f349/tulip/password"
	"github.com/1f349/twofactor"
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

func (t *Tx) InsertUser(name, un, pw, email string, role UserRole, active bool) (uuid.UUID, error) {
	pwHash, err := password.HashPassword(pw)
	if err != nil {
		return uuid.UUID{}, err
	}
	u := uuid.New()
	_, err = t.tx.Exec(`INSERT INTO users (subject, name, username, password, email, role, updated_at, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, u, name, un, pwHash, email, role, updatedAt(), active)
	return u, err
}

func (t *Tx) CheckLogin(un, pw string) (*User, bool, bool, error) {
	var u User
	var hasOtp, hasVerify bool
	row := t.tx.QueryRow(`SELECT subject, password, EXISTS(SELECT 1 FROM otp WHERE otp.subject = users.subject), email, email_verified FROM users WHERE username = ?`, un)
	err := row.Scan(&u.Sub, &u.Password, &hasOtp, &u.Email, &hasVerify)
	if err != nil {
		return nil, false, false, err
	}
	err = password.CheckPasswordHash(u.Password, pw)
	return &u, hasOtp, hasVerify, err
}

func (t *Tx) GetUserDisplayName(sub uuid.UUID) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name FROM users WHERE subject = ? LIMIT 1`, sub.String())
	err := row.Scan(&u.Name)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUserRole(sub uuid.UUID) (UserRole, error) {
	var r UserRole
	row := t.tx.QueryRow(`SELECT role FROM users WHERE subject = ? LIMIT 1`, sub.String())
	err := row.Scan(&r)
	return r, err
}

func (t *Tx) GetUser(sub uuid.UUID) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT name, username, password, picture, website, email, email_verified, pronouns, birthdate, zoneinfo, locale, updated_at, active FROM users WHERE subject = ?`, sub.String())
	err := row.Scan(&u.Name, &u.Username, &u.Password, &u.Picture, &u.Website, &u.Email, &u.EmailVerified, &u.Pronouns, &u.Birthdate, &u.ZoneInfo, &u.Locale, &u.UpdatedAt, &u.Active)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUserEmail(sub uuid.UUID) (string, error) {
	var email string
	row := t.tx.QueryRow(`SELECT email FROM users WHERE subject = ?`, sub.String())
	err := row.Scan(&email)
	return email, err
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

func (t *Tx) SetTwoFactor(sub uuid.UUID, totp *twofactor.Totp) error {
	u, err := totp.ToBytes()
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`INSERT INTO otp(subject, raw) VALUES (?, ?) ON CONFLICT(subject) DO UPDATE SET raw = excluded.raw`, sub.String(), u)
	return err
}

func (t *Tx) GetTwoFactor(sub uuid.UUID, issuer string) (*twofactor.Totp, error) {
	var u []byte
	row := t.tx.QueryRow(`SELECT raw FROM otp WHERE subject = ?`, sub.String())
	err := row.Scan(&u)
	if err != nil {
		return nil, err
	}
	return twofactor.TOTPFromBytes(u, issuer)
}

func (t *Tx) HasTwoFactor(sub uuid.UUID) (bool, error) {
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
	row := t.tx.QueryRow(`SELECT secret, name, domain, sso, active FROM client_store WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&u.Secret, &u.Name, &u.Domain, &u.SSO, &u.Active)
	u.Owner = sub
	if !u.Active {
		return nil, fmt.Errorf("client is not active")
	}
	return &u, err
}

func (t *Tx) GetAppList(offset int) ([]ClientInfoDbOutput, error) {
	var u []ClientInfoDbOutput
	row, err := t.tx.Query(`SELECT subject, name, domain, owner, sso, active FROM client_store LIMIT 25 OFFSET ?`, offset)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		var a ClientInfoDbOutput
		err := row.Scan(&a.Sub, &a.Name, &a.Domain, &a.Owner, &a.SSO, &a.Active)
		if err != nil {
			return nil, err
		}
		u = append(u, a)
	}
	return u, row.Err()
}

func (t *Tx) InsertClientApp(name, domain string, sso, active bool, owner uuid.UUID) error {
	u := uuid.New()
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`INSERT INTO client_store (subject, name, secret, domain, owner, sso, active) VALUES (?, ?, ?, ?, ?, ?, ?)`, u.String(), name, secret, domain, owner.String(), sso, active)
	return err
}

func (t *Tx) UpdateClientApp(subject uuid.UUID, name, domain string, sso, active bool) error {
	_, err := t.tx.Exec(`UPDATE client_store SET name = ?, domain = ?, sso = ?, active = ? WHERE subject = ?`, name, domain, sso, active, subject.String())
	return err
}

func (t *Tx) ResetClientAppSecret(subject uuid.UUID, secret string) error {
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`UPDATE client_store SET secret = ? WHERE subject = ?`, secret, subject.String())
	return err
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

func (t *Tx) UpdateUser(subject uuid.UUID, role UserRole, active bool) error {
	_, err := t.tx.Exec(`UPDATE users SET active = ?, role = ? WHERE subject = ?`, active, role, subject)
	return err
}

func (t *Tx) VerifyUserEmail(sub uuid.UUID) error {
	_, err := t.tx.Exec(`UPDATE users SET email_verified = 1 WHERE subject = ?`, sub.String())
	return err
}

type ClientInfoDbOutput struct {
	Sub, Name, Secret, Domain, Owner string
	SSO, Active                      bool
}
