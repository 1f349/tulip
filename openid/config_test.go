package openid

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenConfig(t *testing.T) {
	assert.Equal(t, Config{
		Issuer:                 "https://example.com",
		AuthorizationEndpoint:  "https://example.com/authorize",
		TokenEndpoint:          "https://example.com/token",
		UserInfoEndpoint:       "https://example.com/userinfo",
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        []string{"openid", "email"},
		ClaimsSupported:        []string{"name", "email", "preferred_username"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}, GenConfig("https://example.com", []string{"openid", "email"}, []string{"name", "email", "preferred_username"}))
}
