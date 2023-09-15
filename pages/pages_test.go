package pages

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEmailHide(t *testing.T) {
	assert.Equal(t, "xx", EmailHide("hi"))
	assert.Equal(t, "xxxxxxx@xxxxxxx.xxx", EmailHide("example@example.com"))
}
