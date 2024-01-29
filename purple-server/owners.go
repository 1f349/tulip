package server

// UserConfig is the structure for storing a user's role and owned domains
type UserConfig map[string]struct {
	Roles   []string `json:"roles"`
	Domains []string `json:"domains"`
}

func (u UserConfig) AllRoles(user string) []string {
	return u[user].Roles
}

func (u UserConfig) HasRole(user, role string) bool {
	for _, i := range u[user].Roles {
		if i == role {
			return true
		}
	}
	return false
}

func (u UserConfig) AllDomains(user string) []string {
	return u[user].Domains
}

func (u UserConfig) OwnsDomain(user, domain string) bool {
	for _, i := range u[user].Domains {
		if i == domain {
			return true
		}
	}
	return false
}
