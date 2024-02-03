package server

import (
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/oauth"
	"net/http"
)

type PurpleAuthSource struct {
	DB     *database.DB
	Signer mjwt.Signer
}

var _ oauth.AuthSource = &PurpleAuthSource{}

func (p *PurpleAuthSource) UserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error) {
	c := req.Cookie("auth")
	if c.Value == "" {
		http.Error(rw, "No auth", http.StatusForbidden)
		return
	}

	_, b, err := mjwt.ExtractClaims[auth.AccessTokenClaims](p.Signer, c.Value)
	if err != nil {
		http.Error(rw, "Invalid token", http.StatusForbidden)
		return
	}

	if b.Issuer!=
}
