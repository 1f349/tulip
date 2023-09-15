package main

type startUpConfig struct {
	Listen      string `json:"listen"`
	Domain      string `json:"domain"`
	OtpIssuer   string `json:"otp_issuer"`
	ServiceName string `json:"service_name"`
}
