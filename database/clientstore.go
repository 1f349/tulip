package database

import (
	"github.com/go-oauth2/oauth2/v4"
)

var _ oauth2.ClientInfo = &ClientStore{}

func (c *ClientStore) GetID() string     { return c.Subject }
func (c *ClientStore) GetSecret() string { return c.Secret }
func (c *ClientStore) GetDomain() string { return c.Domain }
func (c *ClientStore) IsPublic() bool    { return c.Public }
func (c *ClientStore) GetUserID() string { return c.Owner }

// GetName is an extra field for the oauth handler to display the application
// name
func (c *ClientStore) GetName() string { return c.Name }

// IsSSO is an extra field for the oauth handler to skip the user input stage
// this is for trusted applications to get permissions without asking the user
func (c *ClientStore) IsSSO() bool { return c.Sso }

// IsActive is an extra field for the app manager to get the active state
func (c *ClientStore) IsActive() bool { return c.Active }
