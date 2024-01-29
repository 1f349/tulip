package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/oauth"
	"net/http"
	"net/url"
)

type RedAuthSource struct {
	DB *database.DB
}

var _ oauth.AuthSource = &RedAuthSource{}

func (r *RedAuthSource) UserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error) {
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
