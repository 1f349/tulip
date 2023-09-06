package database

import (
	"encoding/json"
	"github.com/MrMelon54/pronouns"
	"github.com/google/uuid"
	"golang.org/x/text/language"
	"net/url"
	"time"
)

type User struct {
	Sub           uuid.UUID         `json:"sub"`
	Name          string            `json:"name,omitempty"`
	Username      string            `json:"username"`
	Password      string            `json:"password"`
	Picture       NullStringScanner `json:"picture,omitempty"`
	Website       NullStringScanner `json:"website,omitempty"`
	Email         string            `json:"email"`
	EmailVerified bool              `json:"email_verified"`
	Pronouns      PronounScanner    `json:"pronouns,omitempty"`
	Birthdate     NullDateScanner   `json:"birthdate,omitempty"`
	ZoneInfo      LocationScanner   `json:"zoneinfo,omitempty"`
	Locale        LocaleScanner     `json:"locale,omitempty"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Active        bool              `json:"active"`
}

type UserPatch struct {
	Name      NullStringScanner `json:"name"`
	Picture   NullStringScanner `json:"picture"`
	Website   NullStringScanner `json:"website"`
	Pronouns  PronounScanner    `json:"pronouns"`
	Birthdate NullDateScanner   `json:"birthdate"`
	ZoneInfo  *time.Location    `json:"zoneinfo"`
	Locale    *language.Tag     `json:"locale"`
}

func (u *UserPatch) UnmarshalJSON(bytes []byte) error {
	var m struct {
		Name      string `json:"name"`
		Picture   string `json:"picture"`
		Website   string `json:"website"`
		Pronouns  string `json:"pronouns"`
		Birthdate string `json:"birthdate"`
		ZoneInfo  string `json:"zoneinfo"`
		Locale    string `json:"locale"`
	}
	err := json.Unmarshal(bytes, &m)
	if err != nil {
		return err
	}
	u.Name = m.Name

	// only parse the picture address if included
	if m.Picture != "" {
		u.Picture, err = url.Parse(m.Picture)
		if err != nil {
			return err
		}
	}

	// only parse the website address if included
	if m.Website != "" {
		u.Website, err = url.Parse(m.Website)
		if err != nil {
			return err
		}
	}

	// only parse the pronouns if included
	if m.Pronouns != "" {
		u.Pronouns, err = pronouns.FindPronoun(m.Pronouns)
		if err != nil {
			return err
		}
	}

	// only parse the birthdate if included
	if m.Birthdate != "" {
		u.Birthdate, err = time.Parse(time.DateOnly, m.Birthdate)
		if err != nil {
			return err
		}
	}

	// only parse the zoneinfo if included
	if m.ZoneInfo != "" {
		u.ZoneInfo, err = time.LoadLocation(m.ZoneInfo)
		if err != nil {
			return err
		}
	}

	if m.Locale != "" {
		locale, err := language.Parse(m.Locale)
		if err != nil {
			return err
		}
		u.Locale = &locale
	}
	return nil
}

var _ json.Unmarshaler = &UserPatch{}
