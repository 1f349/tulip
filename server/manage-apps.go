package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strconv"
)

func (h *HttpServer) ManageAppsGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
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
	var appList []database.ClientInfoDbOutput
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		role, err = tx.GetUserRole(auth.Data.ID)
		if err != nil {
			return
		}
		appList, err = tx.GetAppList(offset)
		return
	}) {
		return
	}

	m := map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"Apps":         appList,
		"Offset":       offset,
		"IsAdmin":      role == database.RoleAdmin,
		"NewAppName":   q.Get("NewAppName"),
		"NewAppSecret": q.Get("NewAppSecret"),
	}
	if q.Has("edit") {
		for _, i := range appList {
			if i.Sub == q.Get("edit") {
				m["Edit"] = i
				goto validEdit
			}
		}
		http.Error(rw, "400 Bad Request: Invalid client app to edit", http.StatusBadRequest)
		return
	}

validEdit:
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-apps", m)
}

func (h *HttpServer) ManageAppsPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "400 Bad Request: Failed to parse form", http.StatusBadRequest)
		return
	}

	offset := req.Form.Get("offset")
	action := req.Form.Get("action")
	name := req.Form.Get("name")
	domain := req.Form.Get("domain")
	sso := req.Form.Has("sso")
	active := req.Form.Has("active")

	if sso {
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
	}

	switch action {
	case "create":
		if h.DbTx(rw, func(tx *database.Tx) error {
			return tx.InsertClientApp(name, domain, sso, active, auth.Data.ID)
		}) {
			return
		}
	case "edit":
		if h.DbTx(rw, func(tx *database.Tx) error {
			sub, err := uuid.Parse(req.Form.Get("subject"))
			if err != nil {
				return err
			}
			return tx.UpdateClientApp(sub, auth.Data.ID, name, domain, sso, active)
		}) {
			return
		}
	case "secret":
		var info oauth2.ClientInfo
		var secret string
		if h.DbTx(rw, func(tx *database.Tx) error {
			sub, err := uuid.Parse(req.Form.Get("subject"))
			if err != nil {
				return err
			}
			info, err = tx.GetClientInfo(sub.String())
			if err != nil {
				return err
			}
			secret, err = tx.ResetClientAppSecret(sub, auth.Data.ID)
			return err
		}) {
			return
		}

		appName := "Unknown..."
		if getName, ok := info.(interface{ GetName() string }); ok {
			appName = getName.GetName()
		}

		h.ManageAppsGet(rw, &http.Request{
			URL: &url.URL{
				RawQuery: url.Values{
					"offset":       []string{offset},
					"NewAppName":   []string{appName},
					"NewAppSecret": []string{secret},
				}.Encode(),
			},
		}, httprouter.Params{}, auth)
		return
	default:
		http.Error(rw, "400 Bad Request: Invalid action", http.StatusBadRequest)
		return
	}

	redirectUrl := url.URL{Path: "/manage/apps", RawQuery: url.Values{"offset": []string{offset}}.Encode()}
	http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
}
