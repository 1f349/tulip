package server

import (
	"fmt"
	"github.com/go-session/session"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
)

func (h *HttpServer) authorizeEndpoint(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	ss, err := session.Start(req.Context(), rw, req)
	if err != nil {
		http.Error(rw, "Failed to load session", http.StatusInternalServerError)
		return
	}

	userID, err := h.oauthSrv.UserAuthorizationHandler(rw, req)
	if err != nil {
		http.Error(rw, "Failed to check user", http.StatusInternalServerError)
		return
	} else if userID == "" {
		return
	}

	// function is only called with GET or POST method
	isPost := req.Method == http.MethodPost

	var form url.Values
	if isPost {
		err = req.ParseForm()
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
		http.Error(rw, "400 Bad Request", http.StatusBadRequest)
		return
	case !isSSO && !isPost:
		f := func(key string) string { return form.Get(key) }
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(rw, `
<!DOCTYPE html>
<html>
<head><title>Authorize</title></head>
<body>
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="%s">
  <input type="hidden" name="redirect_uri" value="%s">
  <input type="hidden" name="scope" value="%s">
  <input type="hidden" name="state" value="%s">
  <input type="hidden" name="nonce" value="%s">
  <input type="hidden" name="response_type" value="%s">
  <input type="hidden" name="response_mode" value="%s">
  <div>Scope: %s</div>
  <div><button type="submit">Authorize</button></div>
  <div><button type="submit" name="cancel" value="">Cancel</button></div>
</form>
</html>`, clientID, redirectUri, f("scope"), f("state"), f("nonce"), f("response_type"), f("response_mode"), f("scope"))
		return
	default:
		break
	}

	// continue flow
	oauthDataRaw, ok := ss.Get("OAuthData")
	if ok {
		ss.Delete("OAuthData")
		if ss.Save() != nil {
			http.Error(rw, "Failed to save session", http.StatusInternalServerError)
			return
		}
		oauthData, ok := oauthDataRaw.(url.Values)
		if !ok {
			http.Error(rw, "Failed to load session", http.StatusInternalServerError)
			return
		}
		req.URL.RawQuery = oauthData.Encode()
	}

	if err := h.oauthSrv.HandleAuthorizeRequest(rw, req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
	}
}

func (h *HttpServer) oauthUserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", err
	}

	auth, err := h.internalAuthenticationHandler(rw, req)
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
		auth.Session.Set("OAuthData", q)
		if auth.Session.Save() != nil {
			http.Error(rw, "Failed to save session", http.StatusInternalServerError)
			return "", err
		}
		http.Redirect(rw, req, "/login?redirect=oauth", http.StatusFound)
		return "", nil
	}
	return auth.ID.String(), nil
}
