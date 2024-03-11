package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUserZone_MarshalJSON(t *testing.T) {
	location, err := time.LoadLocation("Europe/London")
	assert.NoError(t, err)
	assert.Equal(t, "\"Europe/London\"", encode(UserZone{location}))
	assert.Equal(t, "\"UTC\"", encode(UserZone{time.UTC}))
}
