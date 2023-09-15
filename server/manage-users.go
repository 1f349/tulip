package server

import (
	"errors"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strconv"
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

	var role database.UserRole
	var userList []database.User
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		role, err = tx.GetUserRole(auth.Data.ID)
		if err != nil {
			return
		}
		userList, err = tx.GetUserList(offset)
		return
	}) {
		return
	}
	if role != database.RoleAdmin {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	m := map[string]any{
		"ServiceName":  h.serviceName,
		"Users":        userList,
		"Offset":       offset,
		"EmailShow":    req.URL.Query().Has("show-email"),
		"CurrentAdmin": auth.Data.ID,
	}
	if q.Has("edit") {
		for _, i := range userList {
			if i.Sub.String() == q.Get("edit") {
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

	var role database.UserRole
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		role, err = tx.GetUserRole(auth.Data.ID)
		return
	}) {
		return
	}
	if role != database.RoleAdmin {
		http.Error(rw, "400 Bad Request: Only admin users can create SSO client applications", http.StatusBadRequest)
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
		if h.DbTx(rw, func(tx *database.Tx) error {
			return tx.InsertUser(name, username, "", email, newRole, active)
		}) {
			return
		}
	case "edit":
		if h.DbTx(rw, func(tx *database.Tx) error {
			sub, err := uuid.Parse(req.Form.Get("subject"))
			if err != nil {
				return err
			}
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

func parseRoleValue(role string) (database.UserRole, error) {
	switch role {
	case "member":
		return database.RoleMember, nil
	case "admin":
		return database.RoleAdmin, nil
	}
	return 0, errors.New("invalid role value")
}
