package database

import (
	"fmt"
	"github.com/1f349/tulip/database/types"
	"github.com/MrMelon54/pronouns"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/hardfinhq/go-date"
	"golang.org/x/text/language"
	"net/url"
	"time"
)

type UserPatch struct {
	Name      string
	Picture   string
	Website   string
	Pronouns  types.UserPronoun
	Birthdate date.NullDate
	ZoneInfo  types.UserZone
	Locale    types.UserLocale
}

func (u *UserPatch) ParseFromForm(v url.Values) (safeErrs []error) {
	var err error
	u.Name = v.Get("name")
	u.Picture = v.Get("picture")
	u.Website = v.Get("website")
	if v.Has("reset_pronouns") {
		u.Pronouns.Pronoun = pronouns.TheyThem
	} else {
		u.Pronouns.Pronoun, err = pronouns.FindPronoun(v.Get("pronouns"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid pronoun selected"))
		}
	}
	if v.Has("reset_birthdate") || v.Get("birthdate") == "" {
		u.Birthdate = date.NullDate{}
	} else {
		u.Birthdate = date.NullDate{Valid: true}
		u.Birthdate.Date, err = date.FromString(v.Get("birthdate"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid time selected"))
		}
	}
	if v.Has("reset_zoneinfo") {
		u.ZoneInfo.Location = time.UTC
	} else {
		u.ZoneInfo.Location, err = time.LoadLocation(v.Get("zoneinfo"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid timezone selected"))
		}
	}
	if v.Has("reset_locale") {
		u.Locale.Tag = language.AmericanEnglish
	} else {
		u.Locale.Tag, err = language.Parse(v.Get("locale"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid language selected"))
		}
	}
	return
}

var _ oauth2.ClientInfo = &ClientStore{}

func (c *ClientStore) GetID() string     { return c.Subject }
func (c *ClientStore) GetSecret() string { return c.Secret }
func (c *ClientStore) GetDomain() string { return c.Domain }
func (c *ClientStore) IsPublic() bool    { return c.Public }
func (c *ClientStore) GetUserID() string { return c.Owner }

// GetName is an extra field for the oauth handler to display the application
// name
func (c *ClientStore) GetName() string { return c.Name }

// IsSSO is an extra field for the oauth handler to skip the user input stage
// this is for trusted applications to get permissions without asking the user
func (c *ClientStore) IsSSO() bool { return c.Sso }

// IsActive is an extra field for the app manager to get the active state
func (c *ClientStore) IsActive() bool { return c.Active }
