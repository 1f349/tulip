package server

import (
	"errors"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/database/types"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strings"
)

type UserHandler func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth)

type UserAuth struct {
	Subject string
	NeedOtp bool
}

func (u UserAuth) NextFlowUrl(origin *url.URL) *url.URL {
	if u.NeedOtp {
		return PrepareRedirectUrl("/login/otp", origin)
	}
	return nil
}

func (u UserAuth) IsGuest() bool {
	return u.Subject == ""
}

var ErrAuthHttpError = errors.New("auth http error")

func (h *HttpServer) RequireAdminAuthentication(next UserHandler) httprouter.Handle {
	return h.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		var role types.UserRole
		if h.DbTx(rw, func(tx *database.Queries) (err error) {
			role, err = tx.GetUserRole(req.Context(), auth.Subject)
			return
		}) {
			return
		}
		if role != types.RoleAdmin {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) RequireAuthentication(next UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(false, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			redirectUrl := PrepareRedirectUrl("/login", req.URL)
			http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) OptionalAuthentication(flowPart bool, next UserHandler) httprouter.Handle {
	return func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		authData, err := h.internalAuthenticationHandler(rw, req)
		if err != nil {
			if !errors.Is(err, ErrAuthHttpError) {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if n := authData.NextFlowUrl(req.URL); n != nil && !flowPart {
			http.Redirect(rw, req, n.String(), http.StatusFound)
			return
		}
		next(rw, req, params, authData)
	}
}

func (h *HttpServer) internalAuthenticationHandler(rw http.ResponseWriter, req *http.Request) (UserAuth, error) {
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-login-data",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	var u UserAuth
	err := h.readLoginAccessCookie(rw, req, &u)
	if err != nil {
		// not logged in
		return UserAuth{}, nil
	}
	return u, nil
}

func PrepareRedirectUrl(targetPath string, origin *url.URL) *url.URL {
	// find start of query parameters in target path
	n := strings.IndexByte(targetPath, '?')
	v := url.Values{}

	// parse existing query parameters
	if n != -1 {
		q, err := url.ParseQuery(targetPath[n+1:])
		if err != nil {
			panic("PrepareRedirectUrl: invalid hardcoded target path query parameters")
		}
		v = q
		targetPath = targetPath[:n]
	}

	// add path of origin as a new query parameter
	orig := origin.Path
	if origin.RawQuery != "" || origin.ForceQuery {
		orig += "?" + origin.RawQuery
	}
	if orig != "" {
		v.Set("redirect", orig)
	}
	return &url.URL{Path: targetPath, RawQuery: v.Encode()}
}
