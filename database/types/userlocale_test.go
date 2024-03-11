package types

import (
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"testing"
)

func TestUserLocale_MarshalJSON(t *testing.T) {
	assert.Equal(t, "\"en-US\"", encode(UserLocale{language.AmericanEnglish}))
	assert.Equal(t, "\"en-GB\"", encode(UserLocale{language.BritishEnglish}))
}
