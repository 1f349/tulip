package types

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"golang.org/x/text/language"
)

var (
	_ sql.Scanner      = &UserLocale{}
	_ driver.Valuer    = &UserLocale{}
	_ json.Marshaler   = &UserLocale{}
	_ json.Unmarshaler = &UserLocale{}
)

type UserLocale struct{ language.Tag }

func (l *UserLocale) Scan(src any) error {
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

func (l UserLocale) Value() (driver.Value, error) {
	return l.Tag.String(), nil
}

func (l UserLocale) MarshalJSON() ([]byte, error) { return json.Marshal(l.Tag.String()) }

func (l *UserLocale) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return l.Scan(a)
}
