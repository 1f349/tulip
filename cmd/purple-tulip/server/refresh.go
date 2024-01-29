package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/mjwt/claims"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

func (h *HttpServer) refreshHandler(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	ref := strings.TrimSuffix(req.Referer(), "/")
	allowedClient, ok := (*h.services.Load())[ref]
	if !ok {
		http.Error(rw, "Invalid origin", http.StatusBadRequest)
		return
	}
	loginNameCookie, err := req.Cookie("lavender-login-name")
	if err != nil {
		http.Error(rw, "Failed to read cookie", http.StatusBadRequest)
		return
	}
	loginService := h.manager.Load().FindServiceFromLogin(loginNameCookie.Value)
	cookie, err := req.Cookie("sso-exchange")
	if err != nil {
		http.Error(rw, "Failed to read cookie", http.StatusBadRequest)
		return
	}
	rawEncrypt, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusBadRequest)
		return
	}
	rawTokens, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, h.signer.PrivateKey(), rawEncrypt, []byte("sso-exchange"))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusBadRequest)
		return
	}
	var exchange oauth2.Token
	err = json.Unmarshal(rawTokens, &exchange)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusBadRequest)
		return
	}
	h.finishTokenGenerateFlow(rw, req, flowStateData{
		sso:    loginService,
		target: allowedClient,
	}, &exchange, func(accessToken string, refreshToken string, v3 map[string]any) {
		tokens := map[string]any{
			"target":   allowedClient.Url.String(),
			"userinfo": v3,
			"tokens": map[string]any{
				"access":  accessToken,
				"refresh": refreshToken,
			},
		}
		_ = json.NewEncoder(rw).Encode(tokens)
	})
}

func (h *HttpServer) finishTokenGenerateFlow(rw http.ResponseWriter, req *http.Request, v flowStateData, exchange *oauth2.Token, response func(accessToken string, refreshToken string, v3 map[string]any)) {
	// fetch user info
	v2, err := testOa2UserInfo(v.sso, req.Context(), exchange)
	if err != nil {
		fmt.Println("Failed to get userinfo:", err)
		http.Error(rw, "Failed to get userinfo", http.StatusInternalServerError)
		return
	}
	defer v2.Body.Close()
	if v2.StatusCode != http.StatusOK {
		http.Error(rw, "Failed to get userinfo: unexpected status code", http.StatusInternalServerError)
		return
	}

	// encrypt exchange tokens for cookie storage
	marshal, err := json.Marshal(exchange)
	if err != nil {
		fmt.Println("Failed to marshal exchange tokens", err)
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}
	oaepBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, h.signer.PublicKey(), marshal, []byte("sso-exchange"))
	if err != nil {
		fmt.Println("Failed to encrypt exchange tokens", err)
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "sso-exchange",
		Value:    base64.RawURLEncoding.EncodeToString(oaepBytes),
		Path:     "/",
		Expires:  time.Now().AddDate(0, 3, 0),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	var v3 map[string]any
	if err = json.NewDecoder(v2.Body).Decode(&v3); err != nil {
		fmt.Println("Failed to decode userinfo:", err)
		http.Error(rw, "Failed to decode userinfo", http.StatusInternalServerError)
		return
	}

	sub, ok := v3["sub"].(string)
	if !ok {
		http.Error(rw, "Invalid subject in userinfo", http.StatusInternalServerError)
		return
	}
	aud, ok := v3["aud"].(string)
	if !ok {
		http.Error(rw, "Invalid audience in userinfo", http.StatusInternalServerError)
		return
	}

	var needsMailFlag, needsDomains bool

	ps := claims.NewPermStorage()
	for _, i := range v.target.Permissions {
		if strings.HasPrefix(i, "dynamic:") {
			switch i {
			case "dynamic:mail-inbox":
				needsMailFlag = true
			case "dynamic:domain-owns":
				needsDomains = true
			}
		} else {
			ps.Set(i)
		}
	}

	if needsMailFlag {
		if verified, ok := v3["email_verified"].(bool); ok && verified {
			if mailAddress, ok := v3["email"].(string); ok {
				address, err := mail.ParseAddress(mailAddress)
				if err != nil {
					http.Error(rw, "Invalid email in userinfo", http.StatusInternalServerError)
					return
				}
				n := strings.IndexByte(address.Address, '@')
				if n != -1 {
					if address.Address[n+1:] == v.sso.Config.Namespace {
						ps.Set("mail:inbox=" + address.Address)
					}
				}
			}
		}
	}

	if needsDomains {
		a := h.conf.Load().Users.AllDomains(sub + "@" + v.sso.Config.Namespace)
		for _, i := range a {
			ps.Set("domain:owns=" + i)
		}
	}

	nsSub := sub + "@" + v.sso.Config.Namespace
	ati := uuidNewStringAti()
	accessToken, err := h.signer.GenerateJwt(nsSub, ati, jwt.ClaimStrings{aud}, 15*time.Minute, auth.AccessTokenClaims{
		Perms: ps,
	})
	if err != nil {
		http.Error(rw, "Error generating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.signer.GenerateJwt(nsSub, uuidNewStringRti(), jwt.ClaimStrings{aud}, 15*time.Minute, auth.RefreshTokenClaims{AccessTokenId: ati})
	if err != nil {
		http.Error(rw, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	response(accessToken, refreshToken, v3)
}
