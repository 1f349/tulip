package server

import (
	"fmt"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
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
		auth, err := h.internalAuthenticationHandler(rw, req)
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

func (h *HttpServer) internalAuthenticationHandler(rw http.ResponseWriter, req *http.Request) (UserAuth, error) {
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
	v := url.Values{}
	orig := origin.Path
	if origin.RawQuery != "" || origin.ForceQuery {
		orig += "?" + origin.RawQuery
	}
	if orig != "" {
		v.Set("redirect", orig)
	}
	return &url.URL{Path: targetPath, RawQuery: v.Encode()}
}
