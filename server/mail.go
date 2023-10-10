package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/emersion/go-message/mail"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) MailVerify(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	code := params.ByName("code")
	parse, err := uuid.Parse(code)
	if err != nil {
		http.Error(rw, "Invalid email verification code", http.StatusBadRequest)
		return
	}

	k := mailLinkKey{mailLinkVerifyEmail, parse}

	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid email verification code", http.StatusBadRequest)
		return
	}
	if h.DbTx(rw, func(tx *database.Tx) error {
		return tx.VerifyUserEmail(userSub)
	}) {
		return
	}

	h.mailLinkCache.Delete(k)

	http.Error(rw, "Email address has been verified, you may close this tab and return to the login page.", http.StatusOK)
}

func (h *HttpServer) MailPassword(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	code := params.ByName("code")
	parse, err := uuid.Parse(code)
	if err != nil {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}

	k := mailLinkKey{mailLinkResetPassword, parse}

	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}

	h.mailLinkCache.Delete(k)

	ss, err := session.Start(req.Context(), rw, req)
	if err != nil {
		http.Error(rw, "Error loading session", http.StatusInternalServerError)
		return
	}

	ss.Set("mail-reset-password-user", userSub)
	err = ss.Save()
	if err != nil {
		http.Error(rw, "Error saving session", http.StatusInternalServerError)
		return
	}

	pages.RenderPageTemplate(rw, "reset-password", map[string]any{
		"ServiceName": h.conf.ServiceName,
	})
}

func (h *HttpServer) MailPasswordPost(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	pw := req.PostFormValue("new_password")
	rpw := req.PostFormValue("confirm_password")

	// reverse passwords are possible
	if len(pw) == 0 {
		http.Error(rw, "Cannot set an empty password", http.StatusBadRequest)
		return
	}
	// bcrypt only allows up to 72 bytes anyway
	if len(pw) > 64 {
		http.Error(rw, "Security by extremely long password is a weird flex", http.StatusBadRequest)
		return
	}
	if rpw != pw {
		http.Error(rw, "Passwords do not match", http.StatusBadRequest)
		return
	}

	// start session
	ss, err := session.Start(req.Context(), rw, req)
	if err != nil {
		http.Error(rw, "Error loading session", http.StatusInternalServerError)
		return
	}

	// get user to reset password for from session
	userRaw, found := ss.Get("mail-reset-password-user")
	if !found {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}
	userSub, ok := userRaw.(uuid.UUID)
	if !ok {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}

	// reset password database call
	if h.DbTx(rw, func(tx *database.Tx) error {
		return tx.UserResetPassword(userSub, pw)
	}) {
		return
	}

	http.Error(rw, "Reset password successfully, you can login now.", http.StatusOK)
}

func (h *HttpServer) MailDelete(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	code := params.ByName("code")
	parse, err := uuid.Parse(code)
	if err != nil {
		http.Error(rw, "Invalid email delete code", http.StatusBadRequest)
		return
	}

	k := mailLinkKey{mailLinkDelete, parse}

	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid email delete code", http.StatusBadRequest)
		return
	}
	var userInfo *database.User
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		userInfo, err = tx.GetUser(userSub)
		if err != nil {
			return
		}
		return tx.UpdateUser(userSub, database.RoleToDelete, false)
	}) {
		return
	}

	h.mailLinkCache.Delete(k)

	// parse email for headers
	address, err := mail.ParseAddress(userInfo.Email)
	if err != nil {
		http.Error(rw, "500 Internal Server Error: Failed to parse user email address", http.StatusInternalServerError)
		return
	}

	err = h.conf.Mail.SendEmailTemplate("mail-account-delete", "Account Deletion", userInfo.Name, address, nil)
	if err != nil {
		http.Error(rw, "Failed to send confirmation email.", http.StatusInternalServerError)
		return
	}

	http.Error(rw, "You will receive an email shortly to verify this action, you may close this tab.", http.StatusOK)
}
