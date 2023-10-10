package server

import (
	"crypto"
	"encoding/base64"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/1f349/twofactor"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"net/http"
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
	var otp *twofactor.Totp
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		hasOtp, err = tx.HasTwoFactor(sub)
		if err != nil {
			return
		}
		if hasOtp {
			otp, err = tx.GetTwoFactor(sub, h.conf.OtpIssuer)
		}
		return
	}) {
		return true
	}

	if hasOtp {
		defer func() {
			h.DbTx(rw, func(tx *database.Tx) error {
				return tx.SetTwoFactor(sub, otp)
			})
		}()

		err := otp.Validate(code)
		if err != nil {
			http.Error(rw, "400 Bad Request: Invalid OTP code", http.StatusBadRequest)
			return true
		}
	}

	return false
}

func (h *HttpServer) EditOtpGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var digits = 0
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

	var otp *twofactor.Totp

	otpRaw, ok := auth.Session.Get("temp-otp")
	if ok {
		if otp, ok = otpRaw.(*twofactor.Totp); !ok {
			http.Error(rw, "400 Bad Request: invalid session, try clearing your cookies", http.StatusBadRequest)
			return
		}

		// check OTP code matches number of digits
		tempCode, err := otp.OTP()
		if err != nil || len(tempCode) != digits {
			otp = nil
		}
	}

	// make a new otp handler if needed
	if otp == nil {
		// get user email
		var email string
		if h.DbTx(rw, func(tx *database.Tx) error {
			var err error
			email, err = tx.GetUserEmail(auth.Data.ID)
			return err
		}) {
			return
		}

		// generate OTP key
		var err error
		otp, err = twofactor.NewTOTP(email, h.conf.OtpIssuer, crypto.SHA512, digits)
		if err != nil {
			http.Error(rw, "500 Internal Server Error: Failed to generate OTP key", http.StatusInternalServerError)
			return
		}

		// save otp key
		auth.Session.Set("temp-otp", otp)
		err = auth.Session.Save()
		if err != nil {
			http.Error(rw, "500 Internal Server Error: Failed to save session", http.StatusInternalServerError)
			return
		}
	}

	// get qr and url
	otpQr, err := otp.QR()
	if err != nil {
		http.Error(rw, "500 Internal Server Error: Failed to generate OTP QR code", http.StatusInternalServerError)
		return
	}
	otpUrl, err := otp.URL()
	if err != nil {
		http.Error(rw, "500 Internal Server Error: Failed to generate OTP URL", http.StatusInternalServerError)
		return
	}

	// render page
	pages.RenderPageTemplate(rw, "edit-otp", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"OtpQr":       template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(otpQr)),
		"OtpUrl":      otpUrl,
	})
}

func (h *HttpServer) EditOtpPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var otp *twofactor.Totp

	otpRaw, ok := auth.Session.Get("temp-otp")
	if !ok {
		http.Error(rw, "400 Bad Request: invalid session, try clearing your cookies", http.StatusBadRequest)
		return
	}
	if otp, ok = otpRaw.(*twofactor.Totp); !ok {
		http.Error(rw, "400 Bad Request: invalid session, try clearing your cookies", http.StatusBadRequest)
		return
	}
	err := otp.Validate(req.FormValue("code"))
	if err != nil {
		http.Error(rw, "400 Bad Request: invalid OTP code", http.StatusBadRequest)
		return
	}

	if h.DbTx(rw, func(tx *database.Tx) error {
		return tx.SetTwoFactor(auth.Data.ID, otp)
	}) {
		return
	}

	http.Redirect(rw, req, "/", http.StatusFound)
}
