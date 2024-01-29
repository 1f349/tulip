package server

import (
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/violet/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) verifyHandler(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// find bearer token
	bearer := utils.GetBearer(req)
	if bearer == "" {
		http.Error(rw, "Missing bearer", http.StatusForbidden)
		return
	}

	// after this mjwt is considered valid
	_, b, err := mjwt.ExtractClaims[auth.AccessTokenClaims](h.signer, bearer)
	if err != nil {
		http.Error(rw, "Invalid token", http.StatusForbidden)
		return
	}

	// check issuer against config
	if b.Issuer != h.conf.Load().Issuer {
		http.Error(rw, "Invalid issuer", http.StatusBadRequest)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
