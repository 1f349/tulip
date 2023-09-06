package openid

type Config struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	ClaimsSupported        []string `json:"claims_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
}

func GenConfig(domain string, scopes, claims []string) Config {
	return Config{
		Issuer:                 "https://" + domain,
		AuthorizationEndpoint:  "https://" + domain + "/authorize",
		TokenEndpoint:          "https://" + domain + "/token",
		UserInfoEndpoint:       "https://" + domain + "/userinfo",
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        scopes,
		ClaimsSupported:        claims,
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}
}
