package server

import (
	"bytes"
	"encoding/base64"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"html/template"
	"image/png"
	"net/http"
	"time"
)

func (h *HttpServer) LoginOtpGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.Data.NeedOtp {
		h.SafeRedirect(rw, req)
		return
	}

	pages.RenderPageTemplate(rw, "login-otp", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Redirect":    req.URL.Query().Get("redirect"),
	})
}

func (h *HttpServer) LoginOtpPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.Data.NeedOtp {
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	otpInput := req.FormValue("code")
	if h.fetchAndValidateOtp(rw, auth.Data.ID, otpInput) {
		return
	}

	auth.Data.NeedOtp = false
	if auth.SaveSessionData() != nil {
		http.Error(rw, "500 Internal Server Error: Failed to safe session", http.StatusInternalServerError)
		return
	}

	h.SafeRedirect(rw, req)
}

func (h *HttpServer) fetchAndValidateOtp(rw http.ResponseWriter, sub uuid.UUID, code string) bool {
	var hasOtp bool
	var secret string
	var digits int
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		hasOtp, err = tx.HasTwoFactor(sub)
		if err != nil {
			return
		}
		if hasOtp {
			secret, digits, err = tx.GetTwoFactor(sub)
		}
		return
	}) {
		return true
	}

	if hasOtp {
		totp := gotp.NewTOTP(secret, digits, 30, nil)
		if !verifyTotp(totp, code) {
			http.Error(rw, "400 Bad Request: Invalid OTP code", http.StatusBadRequest)
			return true
		}
	}

	return false
}

func (h *HttpServer) EditOtpGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var digits int
	switch req.URL.Query().Get("digits") {
	case "6":
		digits = 6
	case "7":
		digits = 7
	case "8":
		digits = 8
	default:
		http.Error(rw, "400 Bad Request: Invalid number of digits for OTP code", http.StatusBadRequest)
		return
	}

	// get user email
	var email string
	if h.DbTx(rw, func(tx *database.Tx) error {
		var err error
		email, err = tx.GetUserEmail(auth.Data.ID)
		return err
	}) {
		return
	}

	secret := gotp.RandomSecret(64)
	if secret == "" {
		http.Error(rw, "500 Internal Server Error: failed to generate OTP secret", http.StatusInternalServerError)
		return
	}
	totp := gotp.NewTOTP(secret, digits, 30, nil)
	otpUri := totp.ProvisioningUri(email, h.conf.OtpIssuer)
	code, err := qrcode.New(otpUri, qrcode.Medium)
	if err != nil {
		http.Error(rw, "500 Internal Server Error: failed to generate QR code", http.StatusInternalServerError)
		return
	}
	qrImg := code.Image(60 * 4)
	qrBounds := qrImg.Bounds()
	qrWidth := qrBounds.Dx()

	qrBuf := new(bytes.Buffer)
	if png.Encode(qrBuf, qrImg) != nil {
		http.Error(rw, "500 Internal Server Error: failed to generate PNG image of QR code", http.StatusInternalServerError)
		return
	}

	// render page
	pages.RenderPageTemplate(rw, "edit-otp", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"OtpQr":       template.URL("data:qrImg/png;base64," + base64.StdEncoding.EncodeToString(qrBuf.Bytes())),
		"QrWidth":     qrWidth,
		"OtpUrl":      otpUri,
		"OtpSecret":   secret,
		"OtpDigits":   digits,
	})
}

func (h *HttpServer) EditOtpPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var digits int
	switch req.FormValue("digits") {
	case "6":
		digits = 6
	case "7":
		digits = 7
	case "8":
		digits = 8
	default:
		http.Error(rw, "400 Bad Request: Invalid number of digits for OTP code", http.StatusBadRequest)
		return
	}

	secret := req.FormValue("secret")
	if !gotp.IsSecretValid(secret) {
		http.Error(rw, "400 Bad Request: Invalid secret", http.StatusBadRequest)
		return
	}

	totp := gotp.NewTOTP(secret, digits, 30, nil)

	if !verifyTotp(totp, req.FormValue("code")) {
		http.Error(rw, "400 Bad Request: invalid OTP code", http.StatusBadRequest)
		return
	}

	http.Redirect(rw, req, "/", http.StatusFound)
}

func verifyTotp(totp *gotp.TOTP, code string) bool {
	t := time.Now()
	if totp.VerifyTime(code, t) {
		return true
	}
	if totp.VerifyTime(code, t.Add(-30*time.Second)) {
		return true
	}
	return totp.VerifyTime(code, t.Add(30*time.Second))
}
