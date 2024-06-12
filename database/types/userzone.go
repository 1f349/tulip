package types

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

var (
	_ sql.Scanner      = &UserZone{}
	_ driver.Valuer    = &UserZone{}
	_ json.Marshaler   = &UserZone{}
	_ json.Unmarshaler = &UserZone{}
)

type UserZone struct{ *time.Location }

func (l *UserZone) Scan(src any) error {
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

func (l UserZone) Value() (driver.Value, error) {
	return l.Location.String(), nil
}

func (l UserZone) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.Location.String())
}

func (l *UserZone) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return l.Scan(a)
}
