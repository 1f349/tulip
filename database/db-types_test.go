package database

import (
	"encoding/json"
	"github.com/MrMelon54/pronouns"
	"github.com/stretchr/testify/assert"
	"maps"
	"testing"
	"time"
)

func TestUserPatch_UnmarshalJSON(t *testing.T) {
	const a = `{
  "name": "Test",
  "picture": "https://example.com/logo.png",
  "website": "https://example.com",
  "gender": "robot",
  "pronouns": "they/them",
  "birthdate": "3070-01-01",
  "zoneinfo": "Europe/London",
  "locale": "en-GB"
}`
	var p UserPatch
	assert.NoError(t, json.Unmarshal([]byte(a), &p))
	assert.Equal(t, "Test", p.Name)
	assert.Equal(t, "https://example.com/logo.png", p.Picture.String())
	assert.Equal(t, "https://example.com", p.Website.String())
	assert.Equal(t, pronouns.TheyThem, p.Pronouns)
	assert.Equal(t, time.Date(3070, time.January, 1, 0, 0, 0, 0, time.UTC), p.Birthdate)
	location, err := time.LoadLocation("Europe/London")
	assert.NoError(t, err)
	assert.Equal(t, location, p.ZoneInfo)
	assert.Equal(t, "en-GB", p.Locale.String())
}

func TestUserPatch_UnmarshalJSON2(t *testing.T) {
	var userModifyChecks = map[string]struct{ valid, invalid []string }{
		"picture":   {valid: []string{"https://example.com/icon.png"}, invalid: []string{"%/icon.png"}},
		"website":   {valid: []string{"https://example.com"}, invalid: []string{"%/example.com"}},
		"pronouns":  {valid: []string{"he/him", "she/her"}, invalid: []string{"a/a"}},
		"birthdate": {valid: []string{"2023-08-07", "2023-01-01"}, invalid: []string{"2023-00-00", "hello"}},
		"zoneinfo": {
			valid:   []string{"Europe/London", "Europe/Berlin", "America/Los_Angeles", "America/Edmonton", "America/Montreal"},
			invalid: []string{"Europe/York", "Canada/Edmonton", "hello"},
		},
		"locale": {valid: []string{"en-GB", "en-US", "zh-CN"}, invalid: []string{"en-YY"}},
	}
	m := map[string]string{
		"name":      "Test",
		"picture":   "https://example.com/logo.png",
		"website":   "https://example.com",
		"gender":    "robot",
		"pronouns":  "they/them",
		"birthdate": "3070-01-01",
		"zoneinfo":  "Europe/London",
		"locale":    "en-GB",
	}
	for k, v := range userModifyChecks {
		t.Run(k, func(t *testing.T) {
			m2 := maps.Clone(m)
			for _, i := range v.valid {
				m2[k] = i
				marshal, err := json.Marshal(m2)
				assert.NoError(t, err)
				var m3 UserPatch
				assert.NoError(t, json.Unmarshal(marshal, &m3))
			}
			for _, i := range v.invalid {
				m2[k] = i
				marshal, err := json.Marshal(m2)
				assert.NoError(t, err)
				var m3 UserPatch
				assert.Error(t, json.Unmarshal(marshal, &m3))
			}
		})
	}
}
