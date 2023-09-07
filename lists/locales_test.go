package lists

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestListLocale(t *testing.T) {
	locales := ListLocale()
	assert.True(t, len(locales) > 4)
	assert.Equal(t, struct{ Value, Label string }{Value: "af", Label: "Afrikaans"}, locales[0])
	assert.Equal(t, struct{ Value, Label string }{Value: "am", Label: "አማርኛ"}, locales[1])
	assert.Equal(t, struct{ Value, Label string }{Value: "zh-Hant", Label: "繁體中文"}, locales[len(locales)-2])
	assert.Equal(t, struct{ Value, Label string }{Value: "zu", Label: "isiZulu"}, locales[len(locales)-1])
}
