package database

import (
	"database/sql"
	"encoding/json"
	"github.com/MrMelon54/pronouns"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"testing"
	"time"
)

func encode(data any) string {
	j, err := json.Marshal(map[string]any{"value": data})
	if err != nil {
		panic(err)
	}
	return string(j)
}

func TestStringScanner_MarshalJSON(t *testing.T) {
	assert.Equal(t, "{\"value\":\"Hello world\"}", encode(NullStringScanner{sql.NullString{String: "Hello world", Valid: true}}))
	assert.Equal(t, "{\"value\":null}", encode(NullStringScanner{sql.NullString{String: "Hello world", Valid: false}}))
}

func TestDateScanner_MarshalJSON(t *testing.T) {
	location, err := time.LoadLocation("Europe/London")
	assert.NoError(t, err)
	assert.Equal(t, "{\"value\":\"2006-01-02\"}", encode(NullDateScanner{sql.NullTime{Time: time.Date(2006, time.January, 2, 0, 0, 0, 0, time.UTC), Valid: true}}))
	assert.Equal(t, "{\"value\":\"2006-08-01\"}", encode(NullDateScanner{sql.NullTime{Time: time.Date(2006, time.August, 2, 0, 0, 0, 0, location), Valid: true}}))
	assert.Equal(t, "{\"value\":null}", encode(NullDateScanner{}))
}

func TestLocationScanner_MarshalJSON(t *testing.T) {
	location, err := time.LoadLocation("Europe/London")
	assert.NoError(t, err)
	assert.Equal(t, "{\"value\":\"Europe/London\"}", encode(LocationScanner{location}))
	assert.Equal(t, "{\"value\":\"UTC\"}", encode(LocationScanner{time.UTC}))
}

func TestLocaleScanner_MarshalJSON(t *testing.T) {
	assert.Equal(t, "{\"value\":\"en-US\"}", encode(LocaleScanner{language.AmericanEnglish}))
	assert.Equal(t, "{\"value\":\"en-GB\"}", encode(LocaleScanner{language.BritishEnglish}))
}

func TestPronounScanner_MarshalJSON(t *testing.T) {
	assert.Equal(t, "{\"value\":\"they/them\"}", encode(PronounScanner{pronouns.TheyThem}))
	assert.Equal(t, "{\"value\":\"he/him\"}", encode(PronounScanner{pronouns.HeHim}))
	assert.Equal(t, "{\"value\":\"she/her\"}", encode(PronounScanner{pronouns.SheHer}))
	assert.Equal(t, "{\"value\":\"it/its\"}", encode(PronounScanner{pronouns.ItIts}))
	assert.Equal(t, "{\"value\":\"one/one's\"}", encode(PronounScanner{pronouns.OneOnes}))
}
