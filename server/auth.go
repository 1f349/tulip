package server

import (
	"fmt"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

type UserHandler func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth)

type UserAuth struct {
	ID      uuid.UUID
	Session session.Store
}

func (u UserAuth) IsGuest() bool {
	return u.ID == uuid.Nil
}

func (h *HttpServer) RequireAuthentication(error string, code int, next UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			http.Error(rw, error, code)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) RequireAuthenticationRedirect(redirect string, code int, next UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			http.Redirect(rw, req, redirect, code)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) OptionalAuthentication(next UserHandler) httprouter.Handle {
	return func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		auth, err := h.internalAuthenticationHandler(rw, req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
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

	userIdRaw, ok := ss.Get("user")
	if !ok {
		return UserAuth{Session: ss}, nil
	}
	userId, ok := userIdRaw.(uuid.UUID)
	if !ok {
		ss.Delete("user")
		err := ss.Save()
		if err != nil {
			return UserAuth{Session: ss}, fmt.Errorf("failed to reset invalid session data")
		}
	}
	return UserAuth{ID: userId, Session: ss}, nil
}
