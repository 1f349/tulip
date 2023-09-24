package mail

import (
	"bytes"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"io"
	"net"
	"time"
)

type Mail struct {
	Name     string      `json:"name"`
	Tls      bool        `json:"tls"`
	Server   string      `json:"server"`
	From     FromAddress `json:"from"`
	Username string      `json:"username"`
	Password string      `json:"password"`
}

func (m *Mail) loginInfo() sasl.Client {
	return sasl.NewPlainClient("", m.Username, m.Password)
}

func (m *Mail) mailCall(to []string, r io.Reader) error {
	host, _, err := net.SplitHostPort(m.Server)
	if err != nil {
		return err
	}
	if m.Tls {
		return smtp.SendMailTLS(m.Server, m.loginInfo(), m.From.String(), to, r)
	}
	if host == "localhost" || host == "127.0.0.1" {
		// internals of smtp.SendMail without STARTTLS for localhost testing
		dial, err := smtp.Dial(m.Server)
		if err != nil {
			return err
		}
		err = dial.Auth(m.loginInfo())
		if err != nil {
			return err
		}
		return dial.SendMail(m.From.String(), to, r)
	}
	return smtp.SendMail(m.Server, m.loginInfo(), m.From.String(), to, r)
}

func (m *Mail) genHeaders(subject string, to []*mail.Address, htmlBody bool) mail.Header {
	var h mail.Header
	h.SetDate(time.Now())
	h.SetSubject(subject)
	h.SetAddressList("From", []*mail.Address{m.From.Address})
	h.SetAddressList("To", to)

	if htmlBody {
		h.Set("Content-Type", "text/html; charset=utf-8")
	} else {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	return h
}

func (m *Mail) SendMail(subject string, to []*mail.Address, htmlBody bool, body io.Reader) error {
	// generate the email in this template
	buf := new(bytes.Buffer)
	h := m.genHeaders(subject, to, htmlBody)
	entity, err := message.New(h.Header, body)
	if err != nil {
		return err
	}
	err = entity.WriteTo(buf)
	if err != nil {
		return err
	}

	// convert all to addresses to strings
	toStr := make([]string, len(to))
	for i := range toStr {
		toStr[i] = to[i].String()
	}

	return m.mailCall(toStr, buf)
}
