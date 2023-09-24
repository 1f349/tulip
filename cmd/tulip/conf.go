package main

import "github.com/1f349/tulip/mail"

type startUpConfig struct {
	Listen      string    `json:"listen"`
	BaseUrl     string    `json:"base_url"`
	OtpIssuer   string    `json:"otp_issuer"`
	ServiceName string    `json:"service_name"`
	Mail        mail.Mail `json:"mail"`
}
