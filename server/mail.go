package server

import (
	"github.com/1f349/tulip/database"
	"github.com/emersion/go-message/mail"
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
	http.Error(rw, "Reset password is not functional yet", http.StatusNotImplemented)
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

	err = h.mailer.SendEmailTemplate("mail-account-delete", "Account Deletion", userInfo.Name, address, nil)
	if err != nil {
		http.Error(rw, "Failed to send confirmation email.", http.StatusInternalServerError)
		return
	}

	http.Error(rw, "You will receive an email shortly to verify this action, you may close this tab.", http.StatusOK)
}
