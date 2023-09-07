package database

import (
	"database/sql"
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
	Name      string
	Picture   string
	Website   string
	Pronouns  pronouns.Pronoun
	Birthdate sql.NullTime
	ZoneInfo  *time.Location
	Locale    language.Tag
}

func (u *UserPatch) ParseFromForm(v url.Values) (err error) {
	u.Name = v.Get("name")
	u.Picture = v.Get("picture")
	u.Website = v.Get("website")
	if v.Has("reset_pronouns") {
		u.Pronouns = pronouns.TheyThem
	} else {
		u.Pronouns, err = pronouns.FindPronoun(v.Get("pronouns"))
		if err != nil {
			return err
		}
	}
	if v.Has("reset_birthdate") {
		u.Birthdate = sql.NullTime{}
	} else {
		u.Birthdate = sql.NullTime{Valid: true}
		u.Birthdate.Time, err = time.Parse(time.DateOnly, v.Get("birthdate"))
		if err != nil {
			return err
		}
	}
	if v.Has("reset_zoneinfo") {
		u.ZoneInfo = time.UTC
	} else {
		u.ZoneInfo, err = time.LoadLocation(v.Get("zoneinfo"))
		if err != nil {
			return err
		}
	}
	if v.Has("reset_locale") {
		u.Locale = language.AmericanEnglish
	} else {
		u.Locale, err = language.Parse(v.Get("locale"))
		if err != nil {
			return err
		}
	}
	return nil
}
