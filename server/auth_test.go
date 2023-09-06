package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserAuth_IsGuest(t *testing.T) {
	var u UserAuth
	assert.True(t, u.IsGuest())
}
