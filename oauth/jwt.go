package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"strings"
)

type JWTAccessGenerate struct {
	signer mjwt.Signer
}

func NewJWTAccessGenerate(signer mjwt.Signer) *JWTAccessGenerate {
	return &JWTAccessGenerate{signer}
}

var _ oauth2.AccessGenerate = &JWTAccessGenerate{}

func (j JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	access, err = j.signer.GenerateJwt(data.UserID, "", jwt.ClaimStrings{data.Client.GetID()}, data.TokenInfo.GetAccessExpiresIn(), auth.AccessTokenClaims{})

	if isGenRefresh {
		t := uuid.NewHash(sha256.New(), uuid.New(), []byte(access), 5).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return
}
