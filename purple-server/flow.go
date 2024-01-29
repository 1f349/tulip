package server

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/1f349/tulip/issuer"
	"github.com/1f349/tulip/purple-server/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var uuidNewStringState = uuid.NewString
var uuidNewStringAti = uuid.NewString
var uuidNewStringRti = uuid.NewString

var testOa2Exchange = func(oa2conf oauth2.Config, ctx context.Context, code string) (*oauth2.Token, error) {
	return oa2conf.Exchange(ctx, code)
}

var testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
	client := oidc.OAuth2Config.Client(ctx, exchange)
	return client.Get(oidc.UserInfoEndpoint)
}

func (h *HttpServer) flowPopup(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	cookie, err := req.Cookie("lavender-login-name")
	if err == nil && cookie.Valid() == nil {
		pages.RenderPageTemplate(rw, "flow-popup-memory", map[string]any{
			"ServiceName": h.conf.Load().ServiceName,
			"Origin":      req.URL.Query().Get("origin"),
			"LoginName":   cookie.Value,
		})
		return
	}
	pages.RenderPageTemplate(rw, "flow-popup", map[string]any{
		"ServiceName": h.conf.Load().ServiceName,
		"Origin":      req.URL.Query().Get("origin"),
	})
}

func (h *HttpServer) flowPopupPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if req.PostFormValue("not-you") == "1" {
		http.SetCookie(rw, &http.Cookie{
			Name:     "lavender-login-name",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(rw, req, (&url.URL{
			Path: "/popup",
			RawQuery: url.Values{
				"origin": []string{req.PostFormValue("origin")},
			}.Encode(),
		}).String(), http.StatusFound)
		return
	}
	loginName := req.PostFormValue("loginname")
	login := h.manager.Load().FindServiceFromLogin(loginName)
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return
	}
	// the @ must exist if the service is defined
	n := strings.IndexByte(loginName, '@')
	loginUn := loginName[:n]

	now := time.Now()
	future := now.AddDate(1, 0, 0)
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-name",
		Value:    loginName,
		Path:     "/",
		Expires:  future,
		MaxAge:   int(future.Sub(now).Seconds()),
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	targetOrigin := req.PostFormValue("origin")
	allowedService, found := (*h.services.Load())[targetOrigin]
	if !found {
		http.Error(rw, "Invalid target origin", http.StatusBadRequest)
		return
	}

	// save state for use later
	state := login.Config.Namespace + ":" + uuidNewStringState()
	h.flowState.Set(state, flowStateData{
		login,
		allowedService,
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = h.conf.Load().BaseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))
	http.Redirect(rw, req, nextUrl, http.StatusFound)
}

func (h *HttpServer) flowCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "Error parsing form", http.StatusBadRequest)
		return
	}

	q := req.URL.Query()
	state := q.Get("state")
	n := strings.IndexByte(state, ':')
	if n == -1 || !h.manager.Load().CheckNamespace(state[:n]) {
		http.Error(rw, "Invalid state namespace", http.StatusBadRequest)
		return
	}
	v, found := h.flowState.Get(state)
	if !found {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}

	oa2conf := v.sso.OAuth2Config
	oa2conf.RedirectURL = h.conf.Load().BaseUrl + "/callback"
	exchange, err := testOa2Exchange(oa2conf, context.Background(), q.Get("code"))
	if err != nil {
		fmt.Println("Failed exchange:", err)
		http.Error(rw, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	h.finishTokenGenerateFlow(rw, req, v, exchange, func(accessToken, refreshToken string, v3 map[string]any) {
		pages.RenderPageTemplate(rw, "flow-callback", map[string]any{
			"ServiceName":   h.conf.Load().ServiceName,
			"TargetOrigin":  v.target.Url.String(),
			"TargetMessage": v3,
			"AccessToken":   accessToken,
			"RefreshToken":  refreshToken,
		})
	})
}
