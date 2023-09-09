package scope

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFancyScopeList(t *testing.T) {
	desc := scopeDescription
	scopeDescription = map[string]string{
		"a": "A",
		"b": "B",
		"c": "C",
	}

	assert.Equal(t, []string{"A"}, FancyScopeList("a"))
	assert.Equal(t, []string{"A", "B"}, FancyScopeList("a b"))
	assert.Equal(t, []string{"A", "B", "C"}, FancyScopeList("a b c"))
	assert.Equal(t, []string{"A", "B"}, FancyScopeList("a,b"))
	assert.Equal(t, []string{"A", "B", "C"}, FancyScopeList("a,b,c"))
	assert.Equal(t, []string{"A", "B", "C"}, FancyScopeList("a b,c"))
	assert.Equal(t, []string{"A", "B", "C"}, FancyScopeList("a,b c"))
	assert.Equal(t, []string{"A", "B", "C"}, FancyScopeList("a, b, c"))

	scopeDescription = desc
}
