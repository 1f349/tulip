package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/database/types"
	"github.com/1f349/tulip/pages"
	"github.com/1f349/tulip/password"
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

	var role types.UserRole
	var appList []database.GetAppListRow
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		role, err = tx.GetUserRole(req.Context(), auth.Subject)
		if err != nil {
			return
		}
		appList, err = tx.GetAppList(req.Context(), database.GetAppListParams{
			Owner:   auth.Subject,
			Column2: role == types.RoleAdmin,
			Offset:  int64(offset),
		})
		return
	}) {
		return
	}

	m := map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"Apps":         appList,
		"Offset":       offset,
		"IsAdmin":      role == types.RoleAdmin,
		"NewAppName":   q.Get("NewAppName"),
		"NewAppSecret": q.Get("NewAppSecret"),
	}
	if q.Has("edit") {
		for _, i := range appList {
			if i.Subject == q.Get("edit") {
				m["EditApp"] = i
				rw.Header().Set("Content-Type", "text/html")
				rw.WriteHeader(http.StatusOK)
				pages.RenderPageTemplate(rw, "manage-apps-edit", m)
				return
			}
		}
		http.Error(rw, "400 Bad Request: Invalid client app to edit", http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-apps", m)
}

func (h *HttpServer) ManageAppsCreateGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var roles types.UserRole
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		roles, err = tx.GetUserRole(req.Context(), auth.Subject)
		return
	}) {
		return
	}

	m := map[string]any{
		"ServiceName": h.conf.ServiceName,
		"IsAdmin":     roles == types.RoleAdmin,
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-apps-create", m)
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
	public := req.Form.Has("public")
	sso := req.Form.Has("sso")
	active := req.Form.Has("active")

	if sso {
		var role types.UserRole
		if h.DbTx(rw, func(tx *database.Queries) (err error) {
			role, err = tx.GetUserRole(req.Context(), auth.Subject)
			return
		}) {
			return
		}
		if role != types.RoleAdmin {
			http.Error(rw, "400 Bad Request: Only admin users can create SSO client applications", http.StatusBadRequest)
			return
		}
	}

	switch action {
	case "create":
		if h.DbTx(rw, func(tx *database.Queries) error {
			secret, err := password.GenerateApiSecret(70)
			if err != nil {
				return err
			}
			return tx.InsertClientApp(req.Context(), database.InsertClientAppParams{
				Subject: uuid.NewString(),
				Name:    name,
				Secret:  secret,
				Domain:  domain,
				Owner:   auth.Subject,
				Public:  public,
				Sso:     sso,
				Active:  active,
			})
		}) {
			return
		}
	case "edit":
		if h.DbTx(rw, func(tx *database.Queries) error {
			return tx.UpdateClientApp(req.Context(), database.UpdateClientAppParams{
				Name:    name,
				Domain:  domain,
				Public:  public,
				Sso:     sso,
				Active:  active,
				Subject: req.FormValue("subject"),
				Owner:   auth.Subject,
			})
		}) {
			return
		}
	case "secret":
		var info database.ClientStore
		var secret string
		if h.DbTx(rw, func(tx *database.Queries) error {
			sub := req.Form.Get("subject")
			info, err = tx.GetClientInfo(req.Context(), sub)
			if err != nil {
				return err
			}
			secret, err := password.GenerateApiSecret(70)
			if err != nil {
				return err
			}
			err = tx.ResetClientAppSecret(req.Context(), database.ResetClientAppSecretParams{
				Secret:  secret,
				Subject: sub,
				Owner:   auth.Subject,
			})
			return err
		}) {
			return
		}

		appName := info.GetName()

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
