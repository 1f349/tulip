package server

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/mjwt/claims"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/logger"
	"github.com/1f349/tulip/pages"
	"github.com/emersion/go-message/mail"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
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

func (h *HttpServer) LoginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, userAuth UserAuth) {
	if !userAuth.IsGuest() {
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

func (h *HttpServer) LoginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, userAuth UserAuth) {
	un := req.FormValue("username")
	pw := req.FormValue("password")

	// flags returned from database call
	var userInfo database.CheckLoginResult
	var loginMismatch byte
	var hasOtp bool

	if h.DbTx(rw, func(tx *database.Queries) error {
		loginUser, err := tx.CheckLogin(req.Context(), un, pw)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				loginMismatch = 1
				return nil
			}
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return err
		}

		userInfo = loginUser
		hasOtp = loginUser.HasOtp
		if !loginUser.EmailVerified {
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

			u := uuid.NewString()
			h.mailLinkCache.Set(mailLinkKey{mailLinkVerifyEmail, u}, userInfo.Subject, time.Now().Add(10*time.Minute))

			// try to send email
			err = h.conf.Mail.SendEmailTemplate("mail-verify", "Verify Email", userInfo.Name, address, map[string]any{
				"VerifyUrl": h.conf.BaseUrl + "/mail/verify/" + u,
			})
			if err != nil {
				logger.Logger.Warn("Login: Failed to send verification email", "err", err)
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
	userAuth = UserAuth{
		Subject: userInfo.Subject,
		NeedOtp: hasOtp,
	}

	if h.setLoginDataCookie(rw, userAuth) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
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

const twelveHours = 12 * time.Hour
const oneMonth = 30 * 24 * time.Hour

func (h *HttpServer) setLoginDataCookie(rw http.ResponseWriter, authData UserAuth) bool {
	ps := claims.NewPermStorage()
	if authData.NeedOtp {
		ps.Set("needs-otp")
	}
	accId := uuid.NewString()
	gen, err := h.signingKey.GenerateJwt(authData.Subject, accId, jwt.ClaimStrings{h.conf.BaseUrl}, twelveHours, auth.AccessTokenClaims{Perms: ps})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	ref, err := h.signingKey.GenerateJwt(authData.Subject, uuid.NewString(), jwt.ClaimStrings{h.conf.BaseUrl}, oneMonth, auth.RefreshTokenClaims{AccessTokenId: accId})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-login-access",
		Value:    gen,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-login-refresh",
		Value:    ref,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, 32),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return false
}

func readJwtCookie[T mjwt.Claims](req *http.Request, cookieName string, signingKey mjwt.Verifier) (mjwt.BaseTypeClaims[T], error) {
	loginCookie, err := req.Cookie(cookieName)
	if err != nil {
		return mjwt.BaseTypeClaims[T]{}, err
	}
	_, b, err := mjwt.ExtractClaims[T](signingKey, loginCookie.Value)
	if err != nil {
		return mjwt.BaseTypeClaims[T]{}, err
	}
	return b, nil
}

func (h *HttpServer) readLoginAccessCookie(rw http.ResponseWriter, req *http.Request, u *UserAuth) error {
	loginData, err := readJwtCookie[auth.AccessTokenClaims](req, "tulip-login-access", h.signingKey)
	if err != nil {
		return h.readLoginRefreshCookie(rw, req, u)
	}
	*u = UserAuth{
		Subject: loginData.Subject,
		NeedOtp: loginData.Claims.Perms.Has("needs-otp"),
	}
	return nil
}

func (h *HttpServer) readLoginRefreshCookie(rw http.ResponseWriter, req *http.Request, userAuth *UserAuth) error {
	refreshData, err := readJwtCookie[auth.RefreshTokenClaims](req, "tulip-login-refresh", h.signingKey)
	if err != nil {
		return err
	}

	*userAuth = UserAuth{
		Subject: refreshData.Subject,
		NeedOtp: false,
	}

	if h.setLoginDataCookie(rw, *userAuth) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return fmt.Errorf("failed to save login cookie: %w", ErrAuthHttpError)
	}
	return nil
}

func (h *HttpServer) LoginResetPasswordPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	email := req.PostFormValue("email")
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" {
		http.Error(rw, "Invalid email address format", http.StatusBadRequest)
		return
	}

	var emailExists bool
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		emailExists, err = tx.UserEmailExists(req.Context(), email)
		return err
	}) {
		return
	}

	go h.possiblySendPasswordResetEmail(email, emailExists)

	http.Error(rw, "An email will be send to your inbox if an account with that email address is found", http.StatusOK)
}

func (h *HttpServer) possiblySendPasswordResetEmail(email string, exists bool) {
	// TODO(Melon): Send reset password email template
	_ = email
	_ = exists
}
