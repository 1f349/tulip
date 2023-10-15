package scope

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScopesExist(t *testing.T) {
	desc := scopeDescription
	scopeDescription = map[string]string{
		"a": "A",
		"b": "B",
		"c": "C",
	}

	assert.True(t, ScopesExist("a b c"))
	assert.False(t, ScopesExist("a b d"))
	assert.True(t, ScopesExist("a,b c"))
	assert.False(t, ScopesExist("a,b d"))

	scopeDescription = desc
}

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
