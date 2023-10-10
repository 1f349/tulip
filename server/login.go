package server

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// getUserLoginName finds the `login_name` query parameter within the `/authorize` redirect url
func getUserLoginName(req *http.Request) string {
	q := req.URL.Query()
	if !q.Has("redirect") {
		return ""
	}
	originUrl, err := url.ParseRequestURI(q.Get("redirect"))
	if err != nil {
		return ""
	}
	if originUrl.Path != "/authorize" {
		return ""
	}
	return originUrl.Query().Get("login_name")
}

func (h *HttpServer) LoginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.IsGuest() {
		h.SafeRedirect(rw, req)
		return
	}

	loginName := getUserLoginName(req)

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Redirect":    req.URL.Query().Get("redirect"),
		"Mismatch":    req.URL.Query().Get("mismatch"),
		"LoginName":   loginName,
	})
}

func (h *HttpServer) LoginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	un := req.FormValue("username")
	pw := req.FormValue("password")

	// flags returned from database call
	var userInfo *database.User
	var loginMismatch byte
	var hasOtp bool

	if h.DbTx(rw, func(tx *database.Tx) error {
		loginUser, hasOtpRaw, hasVerifiedEmail, err := tx.CheckLogin(un, pw)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				loginMismatch = 1
				return nil
			}
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return err
		}

		userInfo = loginUser
		hasOtp = hasOtpRaw
		if !hasVerifiedEmail {
			loginMismatch = 2
		}
		return nil
	}) {
		return
	}

	if loginMismatch != 0 {
		originUrl, err := url.Parse(req.FormValue("redirect"))
		if err != nil {
			http.Error(rw, "400 Bad Request: Invalid redirect URL", http.StatusBadRequest)
			return
		}

		// send verify email
		if loginMismatch == 2 {
			// parse email for headers
			address, err := mail.ParseAddress(userInfo.Email)
			if err != nil {
				http.Error(rw, "500 Internal Server Error: Failed to parse user email address", http.StatusInternalServerError)
				return
			}

			u := uuid.New()
			h.mailLinkCache.Set(mailLinkKey{mailLinkVerifyEmail, u}, userInfo.Sub, time.Now().Add(10*time.Minute))

			// try to send email
			err = h.conf.Mail.SendEmailTemplate("mail-verify", "Verify Email", userInfo.Name, address, map[string]any{
				"VerifyUrl": h.conf.BaseUrl + "/mail/verify/" + u.String(),
			})
			if err != nil {
				log.Println("[Tulip] Login: Failed to send verification email:", err)
				http.Error(rw, "500 Internal Server Error: Failed to send verification email", http.StatusInternalServerError)
				return
			}

			// send email successfully, hope the user actually receives it
		}

		redirectUrl := PrepareRedirectUrl(fmt.Sprintf("/login?mismatch=%d", loginMismatch), originUrl)
		http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
		return
	}

	// only continues if the above tx succeeds
	auth.Data = SessionData{
		ID:      userInfo.Sub,
		NeedOtp: hasOtp,
	}
	if auth.SaveSessionData() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	if hasOtp {
		originUrl, err := url.Parse(req.FormValue("redirect"))
		if err != nil {
			http.Error(rw, "400 Bad Request: Invalid redirect URL", http.StatusBadRequest)
			return
		}
		redirectUrl := PrepareRedirectUrl("/login/otp", originUrl)
		http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
		return
	}

	h.SafeRedirect(rw, req)
}

func (h *HttpServer) LoginResetPasswordPost(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	email := req.PostFormValue("email")
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" {
		http.Error(rw, "Invalid email address format", http.StatusBadRequest)
		return
	}

	var emailExists bool
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		emailExists, err = tx.UserEmailExists(email)
		return err
	}) {
		return
	}

	go h.possiblySendPasswordResetEmail(email, emailExists)

	http.Error(rw, "An email will be send to your inbox if an account with that email address is found", http.StatusOK)
}

func (h *HttpServer) possiblySendPasswordResetEmail(email string, exists bool) {
	// TODO(Melon): Send reset password email template
}
