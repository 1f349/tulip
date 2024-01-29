package mail

import (
	"bytes"
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

func (m *Mail) SendMail(subject string, to []*mail.Address, htmlBody, textBody io.Reader) error {
	// generate the email in this template
	buf := new(bytes.Buffer)

	// setup mail headers
	var h mail.Header
	h.SetDate(time.Now())
	h.SetSubject(subject)
	h.SetAddressList("From", []*mail.Address{m.From.Address})
	h.SetAddressList("To", to)
	h.Set("Content-Type", "multipart/alternative")

	// setup html and text alternative headers
	var hHtml, hTxt mail.InlineHeader
	hHtml.Set("Content-Type", "text/html; charset=utf-8")
	hTxt.Set("Content-Type", "text/plain; charset=utf-8")

	createWriter, err := mail.CreateWriter(buf, h)
	if err != nil {
		return err
	}
	inline, err := createWriter.CreateInline()
	if err != nil {
		return err
	}
	partHtml, err := inline.CreatePart(hHtml)
	if err != nil {
		return err
	}
	if _, err := io.Copy(partHtml, htmlBody); err != nil {
		return err
	}
	partTxt, err := inline.CreatePart(hTxt)
	if err != nil {
		return err
	}
	if _, err := io.Copy(partTxt, textBody); err != nil {
		return err
	}

	// convert all to addresses to strings
	toStr := make([]string, len(to))
	for i := range toStr {
		toStr[i] = to[i].String()
	}

	return m.mailCall(toStr, buf)
}
