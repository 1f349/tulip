package lists

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestListZoneInfo(t *testing.T) {
	zoneinfos := ListZoneInfo()
	assert.True(t, len(zoneinfos) > 4)
	assert.Equal(t, "Africa/Abidjan", zoneinfos[0])
	assert.Equal(t, "Africa/Accra", zoneinfos[1])
	assert.Equal(t, "WET", zoneinfos[len(zoneinfos)-2])
	assert.Equal(t, "Zulu", zoneinfos[len(zoneinfos)-1])
}
