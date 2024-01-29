package utils

import (
	"encoding"
	"net/url"
)

type JsonUrl struct {
	*url.URL
}

var _ encoding.TextUnmarshaler = &JsonUrl{}

func (s *JsonUrl) UnmarshalText(text []byte) error {
	parse, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	s.URL = parse
	return nil
}
