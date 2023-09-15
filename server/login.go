package server

import (
	"database/sql"
	"errors"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
)

func (h *HttpServer) LoginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.IsGuest() {
		h.SafeRedirect(rw, req)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName": h.serviceName,
		"Redirect":    req.URL.Query().Get("redirect"),
	})
}

func (h *HttpServer) LoginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	un := req.FormValue("username")
	pw := req.FormValue("password")
	var userSub uuid.UUID
	var hasOtp bool
	if h.DbTx(rw, func(tx *database.Tx) error {
		loginUser, hasOtpRaw, err := tx.CheckLogin(un, pw)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				http.Redirect(rw, req, "/login?mismatch=1", http.StatusFound)
				return nil
			}
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return err
		}
		userSub = loginUser.Sub
		hasOtp = hasOtpRaw
		return nil
	}) {
		return
	}

	// only continues if the above tx succeeds
	auth.Data = SessionData{
		ID:      userSub,
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
