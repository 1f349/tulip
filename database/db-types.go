package database

import (
	"database/sql"
	"fmt"
	"github.com/MrMelon54/pronouns"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"golang.org/x/text/language"
	"net/url"
	"time"
)

type User struct {
	Sub           uuid.UUID         `json:"sub"`
	Name          string            `json:"name,omitempty"`
	Username      string            `json:"username"`
	Picture       NullStringScanner `json:"picture,omitempty"`
	Website       NullStringScanner `json:"website,omitempty"`
	Email         string            `json:"email"`
	EmailVerified bool              `json:"email_verified"`
	Pronouns      PronounScanner    `json:"pronouns,omitempty"`
	Birthdate     NullDateScanner   `json:"birthdate,omitempty"`
	ZoneInfo      LocationScanner   `json:"zoneinfo,omitempty"`
	Locale        LocaleScanner     `json:"locale,omitempty"`
	Role          UserRole          `json:"role"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Active        bool              `json:"active"`
}

type UserRole int

const (
	RoleMember UserRole = iota
	RoleAdmin
	RoleToDelete
)

func (r UserRole) String() string {
	switch r {
	case RoleMember:
		return "Member"
	case RoleAdmin:
		return "Admin"
	case RoleToDelete:
		return "ToDelete"
	}
	return fmt.Sprintf("UserRole{ %d }", r)
}

func (r UserRole) IsValid() bool {
	return r == RoleMember || r == RoleAdmin
}

type UserPatch struct {
	Name      string
	Picture   string
	Website   string
	Pronouns  pronouns.Pronoun
	Birthdate sql.NullTime
	ZoneInfo  *time.Location
	Locale    language.Tag
}

func (u *UserPatch) ParseFromForm(v url.Values) (safeErrs []error) {
	var err error
	u.Name = v.Get("name")
	u.Picture = v.Get("picture")
	u.Website = v.Get("website")
	if v.Has("reset_pronouns") {
		u.Pronouns = pronouns.TheyThem
	} else {
		u.Pronouns, err = pronouns.FindPronoun(v.Get("pronouns"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid pronoun selected"))
		}
	}
	if v.Has("reset_birthdate") || v.Get("birthdate") == "" {
		u.Birthdate = sql.NullTime{}
	} else {
		u.Birthdate = sql.NullTime{Valid: true}
		u.Birthdate.Time, err = time.Parse(time.DateOnly, v.Get("birthdate"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid time selected"))
		}
	}
	if v.Has("reset_zoneinfo") {
		u.ZoneInfo = time.UTC
	} else {
		u.ZoneInfo, err = time.LoadLocation(v.Get("zoneinfo"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid timezone selected"))
		}
	}
	if v.Has("reset_locale") {
		u.Locale = language.AmericanEnglish
	} else {
		u.Locale, err = language.Parse(v.Get("locale"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid language selected"))
		}
	}
	return
}

type ClientInfoDbOutput struct {
	Sub, Name, Secret, Domain, Owner string
	SSO, Active                      bool
}

var _ oauth2.ClientInfo = &ClientInfoDbOutput{}

func (c *ClientInfoDbOutput) GetID() string     { return c.Sub }
func (c *ClientInfoDbOutput) GetSecret() string { return c.Secret }
func (c *ClientInfoDbOutput) GetDomain() string { return c.Domain }
func (c *ClientInfoDbOutput) IsPublic() bool    { return false }
func (c *ClientInfoDbOutput) GetUserID() string { return c.Owner }

// GetName is an extra field for the oauth handler to display the application
// name
func (c *ClientInfoDbOutput) GetName() string { return c.Name }

// IsSSO is an extra field for the oauth handler to skip the user input stage
// this is for trusted applications to get permissions without asking the user
func (c *ClientInfoDbOutput) IsSSO() bool { return c.SSO }

// IsActive is an extra field for the app manager to get the active state
func (c *ClientInfoDbOutput) IsActive() bool { return c.Active }
