package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/1f349/tulip/scope"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
)

func (h *HttpServer) authorizeEndpoint(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	// function is only called with GET or POST method
	isPost := req.Method == http.MethodPost

	var form url.Values
	if isPost {
		err := req.ParseForm()
		if err != nil {
			http.Error(rw, "Failed to parse form", http.StatusInternalServerError)
			return
		}
		form = req.PostForm
	} else {
		form = req.URL.Query()
	}

	clientID := form.Get("client_id")
	client, err := h.oauthMgr.GetClient(req.Context(), clientID)
	if err != nil {
		http.Error(rw, "Invalid client", http.StatusBadRequest)
		return
	}

	redirectUri := form.Get("redirect_uri")
	if redirectUri != client.GetDomain() {
		http.Error(rw, "Incorrect redirect URI", http.StatusBadRequest)
		return
	}

	if form.Has("cancel") {
		uCancel, err := url.Parse(client.GetDomain())
		if err != nil {
			http.Error(rw, "Invalid redirect URI", http.StatusBadRequest)
			return
		}
		q := uCancel.Query()
		q.Set("error", "access_denied")
		uCancel.RawQuery = q.Encode()

		http.Redirect(rw, req, uCancel.String(), http.StatusFound)
		return
	}

	var isSSO bool
	if clientIsSSO, ok := client.(interface{ IsSSO() bool }); ok {
		isSSO = clientIsSSO.IsSSO()
	}

	switch {
	case isSSO && isPost:
		http.Error(rw, "400 Bad Request: Not sure how you even managed to send a POST request for an SSO application", http.StatusBadRequest)
		return
	case !isSSO && !isPost:
		// find application redirect domain and name
		appUrlFull, err := url.Parse(client.GetDomain())
		if err != nil {
			http.Error(rw, "500 Internal Server Error: Failed to parse application redirect URL", http.StatusInternalServerError)
			return
		}
		appDomain := appUrlFull.Scheme + "://" + appUrlFull.Host
		appName := appUrlFull.Host
		if clientGetName, ok := client.(interface{ GetName() string }); ok {
			n := clientGetName.GetName()
			if n != "" {
				appName = n
			}
		}

		var user *database.User
		var hasOtp bool
		if h.DbTx(rw, func(tx *database.Tx) (err error) {
			user, err = tx.GetUserDisplayName(auth.Data.ID)
			if err != nil {
				return
			}
			hasOtp, err = tx.HasTwoFactor(auth.Data.ID)
			if err != nil {
				return
			}
			return
		}) {
			return
		}

		rw.WriteHeader(http.StatusOK)
		pages.RenderPageTemplate(rw, "oauth-authorize", map[string]any{
			"ServiceName":  h.serviceName,
			"AppName":      appName,
			"AppDomain":    appDomain,
			"User":         user,
			"WantsList":    scope.FancyScopeList(form.Get("scope")),
			"ResponseType": form.Get("response_type"),
			"ResponseMode": form.Get("response_mode"),
			"ClientID":     form.Get("client_id"),
			"RedirectUri":  form.Get("redirect_uri"),
			"State":        form.Get("state"),
			"Scope":        form.Get("scope"),
			"Nonce":        form.Get("nonce"),
			"HasOtp":       hasOtp,
		})
		return
	}

	if !isSSO {
		otpInput := req.FormValue("code")
		if h.fetchAndValidateOtp(rw, auth.Data.ID, otpInput) {
			return
		}
	}

	// redirect with an error if the action is not authorize
	if form.Get("oauth_action") == "authorize" || isSSO {
		if err := h.oauthSrv.HandleAuthorizeRequest(rw, req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
		}
		return
	}

	parsedRedirect, err := url.Parse(redirectUri)
	if err != nil {
		http.Error(rw, "400 Bad Request: Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := parsedRedirect.Query()
	q.Set("error", "user_cancelled")
	parsedRedirect.RawQuery = q.Encode()
	http.Redirect(rw, req, parsedRedirect.String(), http.StatusFound)
}

func (h *HttpServer) oauthUserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", err
	}

	auth, err := internalAuthenticationHandler(rw, req)
	if err != nil {
		return "", err
	}

	if auth.IsGuest() {
		// handle redirecting to oauth
		var q url.Values
		switch req.Method {
		case http.MethodPost:
			q = req.PostForm
		case http.MethodGet:
			q = req.URL.Query()
		default:
			http.Error(rw, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return "", err
		}

		redirectUrl := PrepareRedirectUrl("/login", &url.URL{Path: "/authorize", RawQuery: q.Encode()})
		http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
		return "", nil
	}
	return auth.Data.ID.String(), nil
}
