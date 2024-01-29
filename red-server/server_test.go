package red_server

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestParseClaims(t *testing.T) {
	assert.Equal(t, map[string]bool{"openid": true, "email": true}, ParseClaims("openid email"))
	assert.Equal(t, map[string]bool{"openid": true, "profile": true, "email": true}, ParseClaims("openid     profile email"))
	assert.Equal(t, map[string]bool{"openid": true, "email": true}, ParseClaims("openid email "))
	assert.Equal(t, map[string]bool{"openid": true, "email": true}, ParseClaims(" openid email"))
	assert.Equal(t, map[string]bool{"openid": true, "profile": true, "email": true}, ParseClaims(" openid  profile email "))
}

func TestCalculateAge(t *testing.T) {
	lGmt := time.FixedZone("GMT", 0)
	lBst := time.FixedZone("BST", 60*60)

	tPast := time.Date(1939, time.January, 5, 0, 0, 0, 0, lGmt)
	tPastDst := time.Date(2001, time.January, 5, 1, 0, 0, 0, lBst)
	tCur := time.Date(2005, time.January, 5, 0, 30, 0, 0, lGmt)
	tCurDst := time.Date(2005, time.January, 5, 0, 30, 0, 0, lBst)
	tFut := time.Date(2008, time.January, 5, 0, 0, 0, 0, time.UTC)

	ageTimeNow = func() time.Time { return tCur }
	assert.Equal(t, 65, CalculateAge(tPast))
	assert.Equal(t, 3, CalculateAge(tPastDst))
	assert.Equal(t, 0, CalculateAge(tFut))

	ageTimeNow = func() time.Time { return tCurDst }
	assert.Equal(t, 66, CalculateAge(tPast))
	assert.Equal(t, 4, CalculateAge(tPastDst))
	fmt.Println(tPastDst.AddDate(4, 0, 0).UTC(), tCur.UTC())
	assert.Equal(t, 0, CalculateAge(tFut))
}
