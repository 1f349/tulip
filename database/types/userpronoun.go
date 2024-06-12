package types

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/mrmelon54/pronouns"
)

var (
	_ sql.Scanner      = &UserPronoun{}
	_ driver.Valuer    = &UserPronoun{}
	_ json.Marshaler   = &UserPronoun{}
	_ json.Unmarshaler = &UserPronoun{}
)

type UserPronoun struct{ pronouns.Pronoun }

func (p *UserPronoun) Scan(src any) error {
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

func (p UserPronoun) Value() (driver.Value, error) {
	return p.Pronoun.String(), nil
}

func (p UserPronoun) MarshalJSON() ([]byte, error) { return json.Marshal(p.Pronoun.String()) }

func (p *UserPronoun) UnmarshalJSON(bytes []byte) error {
	var a string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	return p.Scan(a)
}
