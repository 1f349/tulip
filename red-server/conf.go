package red_server

import "github.com/1f349/tulip/mail"

type Conf struct {
	Listen      string    `json:"listen"`
	BaseUrl     string    `json:"base_url"`
	OtpIssuer   string    `json:"otp_issuer"`
	ServiceName string    `json:"service_name"`
	Namespace   string    `json:"namespace"`
	Mail        mail.Mail `json:"mail"`
}
