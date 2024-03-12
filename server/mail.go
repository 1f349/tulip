package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/database/types"
	"github.com/1f349/tulip/pages"
	"github.com/emersion/go-message/mail"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) MailVerify(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	code := params.ByName("code")

	k := mailLinkKey{mailLinkVerifyEmail, code}

	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid email verification code", http.StatusBadRequest)
		return
	}
	if h.DbTx(rw, func(tx *database.Queries) error {
		return tx.VerifyUserEmail(req.Context(), userSub)
	}) {
		return
	}

	h.mailLinkCache.Delete(k)

	http.Error(rw, "Email address has been verified, you may close this tab and return to the login page.", http.StatusOK)
}

func (h *HttpServer) MailPassword(rw http.ResponseWriter, _ *http.Request, params httprouter.Params) {
	code := params.ByName("code")

	k := mailLinkKey{mailLinkResetPassword, code}
	_, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}

	pages.RenderPageTemplate(rw, "reset-password", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Code":        code,
	})
}

func (h *HttpServer) MailPasswordPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	pw := req.PostFormValue("new_password")
	rpw := req.PostFormValue("confirm_password")
	code := req.PostFormValue("code")

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

	k := mailLinkKey{mailLinkResetPassword, code}
	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid password reset code", http.StatusBadRequest)
		return
	}

	h.mailLinkCache.Delete(k)

	// reset password database call
	if h.DbTx(rw, func(tx *database.Queries) error {
		return tx.ChangePassword(req.Context(), userSub, pw)
	}) {
		return
	}

	http.Error(rw, "Reset password successfully, you can login now.", http.StatusOK)
}

func (h *HttpServer) MailDelete(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	code := params.ByName("code")

	k := mailLinkKey{mailLinkDelete, code}
	userSub, ok := h.mailLinkCache.Get(k)
	if !ok {
		http.Error(rw, "Invalid email delete code", http.StatusBadRequest)
		return
	}
	var userInfo database.User
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		userInfo, err = tx.GetUser(req.Context(), userSub)
		if err != nil {
			return
		}
		return tx.UpdateUserRole(req.Context(), database.UpdateUserRoleParams{
			Active:  false,
			Role:    types.RoleToDelete,
			Subject: userSub,
		})
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
