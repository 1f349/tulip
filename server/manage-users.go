package server

import (
	"errors"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/database/types"
	"github.com/1f349/tulip/pages"
	"github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (h *HttpServer) ManageUsersGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	offset := 0
	q := req.URL.Query()
	if q.Has("offset") {
		var err error
		offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil {
			http.Error(rw, "400 Bad Request: Invalid offset", http.StatusBadRequest)
			return
		}
	}

	var role types.UserRole
	var userList []database.User
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		role, err = tx.GetUserRole(auth.ID)
		if err != nil {
			return
		}
		userList, err = tx.GetUserList(offset)
		return
	}) {
		return
	}
	if role != types.RoleAdmin {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	m := map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"Users":        userList,
		"Offset":       offset,
		"EmailShow":    req.URL.Query().Has("show-email"),
		"CurrentAdmin": auth.ID,
		"Namespace":    h.conf.Namespace,
	}
	if q.Has("edit") {
		for _, i := range userList {
			if i.Sub == q.Get("edit") {
				m["Edit"] = i
				goto validEdit
			}
		}
		http.Error(rw, "400 Bad Request: Invalid user to edit", http.StatusBadRequest)
		return
	}

validEdit:
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-users", m)
}

func (h *HttpServer) ManageUsersPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "400 Bad Request: Failed to parse form", http.StatusBadRequest)
		return
	}

	var role types.UserRole
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		role, err = tx.GetUserRole(auth.ID)
		return
	}) {
		return
	}
	if role != types.RoleAdmin {
		http.Error(rw, "400 Bad Request: Only admin users can manage users", http.StatusBadRequest)
		return
	}

	offset := req.Form.Get("offset")
	action := req.Form.Get("action")
	name := req.Form.Get("name")
	username := req.Form.Get("username")
	email := req.Form.Get("email")
	newRole, err := parseRoleValue(req.Form.Get("role"))
	if err != nil {
		http.Error(rw, "400 Bad Request: Invalid role", http.StatusBadRequest)
		return
	}
	active := req.Form.Has("active")

	switch action {
	case "create":
		// parse email for headers
		address, err := mail.ParseAddress(email)
		if err != nil {
			http.Error(rw, "500 Internal Server Error: Failed to parse user email address", http.StatusInternalServerError)
			return
		}
		n := strings.IndexByte(address.Address, '@')
		// This case should never happen and fail the above address parsing
		if n == -1 {
			return
		}
		addrDomain := address.Address[n+1:]

		var userSub uuid.UUID
		if h.DbTx(rw, func(tx *database.Queries) (err error) {
			userSub, err = tx.InsertUser(name, username, "", email, addrDomain == h.conf.Namespace, newRole, active)
			return err
		}) {
			return
		}

		u, u2 := uuid.NewString(), uuid.NewString()
		h.mailLinkCache.Set(mailLinkKey{mailLinkResetPassword, u}, userSub.String(), time.Now().Add(10*time.Minute))
		h.mailLinkCache.Set(mailLinkKey{mailLinkDelete, u2}, userSub.String(), time.Now().Add(10*time.Minute))

		err = h.conf.Mail.SendEmailTemplate("mail-register-admin", "Register", name, address, map[string]any{
			"RegisterUrl": h.conf.BaseUrl + "/mail/password/" + u,
		})
		if err != nil {
			log.Println("[Tulip] Login: Failed to send register email:", err)
			http.Error(rw, "500 Internal Server Error: Failed to send register email", http.StatusInternalServerError)
			return
		}
	case "edit":
		if h.DbTx(rw, func(tx *database.Queries) error {
			sub := req.Form.Get("subject")
			return tx.UpdateUser(sub, newRole, active)
		}) {
			return
		}
	default:
		http.Error(rw, "400 Bad Request: Invalid action", http.StatusBadRequest)
		return
	}

	redirectUrl := url.URL{Path: "/manage/users", RawQuery: url.Values{"offset": []string{offset}}.Encode()}
	http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
}

func parseRoleValue(role string) (types.UserRole, error) {
	switch role {
	case "member":
		return types.RoleMember, nil
	case "admin":
		return types.RoleAdmin, nil
	}
	return 0, errors.New("invalid role value")
}
