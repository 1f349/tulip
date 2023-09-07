package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/MrMelon54/pronouns"
	"golang.org/x/text/language"
	"time"
)

var (
	_, _, _, _, _ sql.Scanner      = &NullStringScanner{}, &NullDateScanner{}, &LocationScanner{}, &LocaleScanner{}, &PronounScanner{}
	_, _, _, _, _ json.Marshaler   = &NullStringScanner{}, &NullDateScanner{}, &LocationScanner{}, &LocaleScanner{}, &PronounScanner{}
	_, _, _, _, _ json.Unmarshaler = &NullStringScanner{}, &NullDateScanner{}, &LocationScanner{}, &LocaleScanner{}, &PronounScanner{}
)

func marshalValueOrNull(null bool, data any) ([]byte, error) {
	if null {
		return json.Marshal(nil)
	}
	return json.Marshal(data)
}

type NullStringScanner struct{ sql.NullString }

func (s *NullStringScanner) Null() bool         { return !s.Valid }
func (s *NullStringScanner) Scan(src any) error { return s.NullString.Scan(src) }
func (s NullStringScanner) MarshalJSON() ([]byte, error) {
	return marshalValueOrNull(s.Null(), s.NullString.String)
}
func (s *NullStringScanner) UnmarshalJSON(bytes []byte) error {
	if string(bytes) == "null" {
		return s.Scan(nil)
	}
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return s.Scan(&a)
}
func (s NullStringScanner) String() string {
	if s.Null() {
		return ""
	}
	return s.NullString.String
}

type NullDateScanner struct{ sql.NullTime }

func (t *NullDateScanner) Null() bool         { return !t.Valid }
func (t *NullDateScanner) Scan(src any) error { return t.NullTime.Scan(src) }
func (t NullDateScanner) MarshalJSON() ([]byte, error) {
	return marshalValueOrNull(t.Null(), t.Time.UTC().Format(time.DateOnly))
}
func (t *NullDateScanner) UnmarshalJSON(bytes []byte) error {
	if string(bytes) == "null" {
		return t.Scan(nil)
	}
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return t.Scan(&a)
}
func (t NullDateScanner) String() string {
	if t.Null() {
		return ""
	}
	return t.NullTime.Time.UTC().Format(time.DateOnly)
}

type LocationScanner struct{ *time.Location }

func (l *LocationScanner) Scan(src any) error {
	s, ok := src.(string)
	if !ok {
		return fmt.Errorf("unsupported Scan, storing driver.Value type %T into type %T", src, l)
	}
	loc, err := time.LoadLocation(s)
	if err != nil {
		return err
	}
	l.Location = loc
	return nil
}
func (l LocationScanner) MarshalJSON() ([]byte, error) { return json.Marshal(l.Location.String()) }
func (l *LocationScanner) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return l.Scan(a)
}

type LocaleScanner struct{ language.Tag }

func (l *LocaleScanner) Scan(src any) error {
	s, ok := src.(string)
	if !ok {
		return fmt.Errorf("unsupported Scan, storing driver.Value type %T into type %T", src, l)
	}
	lang, err := language.Parse(s)
	if err != nil {
		return err
	}
	l.Tag = lang
	return nil
}
func (l LocaleScanner) MarshalJSON() ([]byte, error) { return json.Marshal(l.Tag.String()) }
func (l *LocaleScanner) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return l.Scan(a)
}

type PronounScanner struct{ pronouns.Pronoun }

func (p *PronounScanner) Scan(src any) error {
	s, ok := src.(string)
	if !ok {
		return fmt.Errorf("unsupported Scan, storing driver.Value type %T into type %T", src, p)
	}
	pro, err := pronouns.FindPronoun(s)
	if err != nil {
		return err
	}
	p.Pronoun = pro
	return nil
}
func (p PronounScanner) MarshalJSON() ([]byte, error) { return json.Marshal(p.Pronoun.String()) }
func (p *PronounScanner) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return p.Scan(a)
}
