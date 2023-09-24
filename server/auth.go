package server

import (
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strings"
)

type UserHandler func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth)

type UserAuth struct {
	Session session.Store
	Data    SessionData
}

type SessionData struct {
	ID      uuid.UUID
	NeedOtp bool
}

func (u UserAuth) NextFlowUrl(origin *url.URL) *url.URL {
	if u.Data.NeedOtp {
		return PrepareRedirectUrl("/login/otp", origin)
	}
	return nil
}

func (u UserAuth) IsGuest() bool {
	return u.Data.ID == uuid.Nil
}

func (u UserAuth) SaveSessionData() error {
	u.Session.Set("session-data", u.Data)
	return u.Session.Save()
}

func (h *HttpServer) RequireAdminAuthentication(next UserHandler) httprouter.Handle {
	return RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		var role database.UserRole
		if h.DbTx(rw, func(tx *database.Tx) (err error) {
			role, err = tx.GetUserRole(auth.Data.ID)
			return
		}) {
			return
		}
		if role != database.RoleAdmin {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		next(rw, req, params, auth)
	})
}

func RequireAuthentication(next UserHandler) httprouter.Handle {
	return OptionalAuthentication(false, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			redirectUrl := PrepareRedirectUrl("/login", req.URL)
			http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
			return
		}
		next(rw, req, params, auth)
	})
}

func OptionalAuthentication(flowPart bool, next UserHandler) httprouter.Handle {
	return func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		auth, err := internalAuthenticationHandler(rw, req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if n := auth.NextFlowUrl(req.URL); n != nil && !flowPart {
			http.Redirect(rw, req, n.String(), http.StatusFound)
			return
		}
		next(rw, req, params, auth)
	}
}

func internalAuthenticationHandler(rw http.ResponseWriter, req *http.Request) (UserAuth, error) {
	ss, err := session.Start(req.Context(), rw, req)
	if err != nil {
		return UserAuth{}, fmt.Errorf("failed to start session")
	}

	// get auth object
	userIdRaw, ok := ss.Get("session-data")
	if !ok {
		return UserAuth{Session: ss}, nil
	}
	userData, ok := userIdRaw.(SessionData)
	if !ok {
		ss.Delete("session-data")
		err := ss.Save()
		if err != nil {
			return UserAuth{Session: ss}, fmt.Errorf("failed to reset invalid session data")
		}
	}

	return UserAuth{Session: ss, Data: userData}, nil
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
