package types

import (
	"github.com/mrmelon54/pronouns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserPronoun_MarshalJSON(t *testing.T) {
	assert.Equal(t, "\"they/them\"", encode(UserPronoun{pronouns.TheyThem}))
	assert.Equal(t, "\"he/him\"", encode(UserPronoun{pronouns.HeHim}))
	assert.Equal(t, "\"she/her\"", encode(UserPronoun{pronouns.SheHer}))
	assert.Equal(t, "\"it/its\"", encode(UserPronoun{pronouns.ItIts}))
	assert.Equal(t, "\"one/one's\"", encode(UserPronoun{pronouns.OneOnes}))
}
