package server

import (
	"github.com/1f349/tulip/issuer"
	"github.com/1f349/tulip/utils"
)

type Conf struct {
	Listen         string             `json:"listen"`
	BaseUrl        string             `json:"base_url"`
	ServiceName    string             `json:"service_name"`
	Issuer         string             `json:"issuer"`
	SsoServices    []issuer.SsoConfig `json:"sso_services"`
	AllowedClients []AllowedClient    `json:"allowed_clients"`
	Users          UserConfig         `json:"users"`
}

type AllowedClient struct {
	Url         utils.JsonUrl `json:"url"`
	Permissions []string      `json:"permissions"`
}
