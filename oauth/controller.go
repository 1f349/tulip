package oauth

import (
	"github.com/1f349/mjwt"
	"github.com/1f349/tulip/openid"
	scope2 "github.com/1f349/tulip/utils"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var errInvalidScope = errors.New("missing required scope")

type Controller struct {
	baseUrl string
	mgr     *manage.Manager
	srv     *server.Server
	OidConf openid.Config
}

type AuthSource interface {
	UserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error)
}

func NewOAuthController(signer mjwt.Signer, source AuthSource, clientStore oauth2.ClientStore, oidConf openid.Config) *Controller {
	c := &Controller{
		// remove last slash from baseUrl
		baseUrl: strings.TrimSuffix(oidConf.Issuer, "/"),
		mgr:     manage.NewDefaultManager(),
		OidConf: oidConf,
	}
	c.srv = server.NewServer(server.NewConfig(), c.mgr)

	c.mgr.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	c.mgr.MustTokenStorage(store.NewMemoryTokenStore())
	c.mgr.MapAccessGenerate(NewJWTAccessGenerate(signer))
	c.mgr.MapClientStorage(clientStore)

	c.srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Printf("Response error: %#v\n", re)
	})
	c.srv.SetClientInfoHandler(func(req *http.Request) (clientID, clientSecret string, err error) {
		cId, cSecret, err := server.ClientBasicHandler(req)
		if cId == "" && cSecret == "" {
			cId, cSecret, err = server.ClientFormHandler(req)
		}
		if err != nil {
			return "", "", err
		}
		return cId, cSecret, nil
	})
	c.srv.SetUserAuthorizationHandler(source.UserAuthorization)
	c.srv.SetAuthorizeScopeHandler(func(rw http.ResponseWriter, req *http.Request) (scope string, err error) {
		var form url.Values
		if req.Method == http.MethodPost {
			form = req.PostForm
		} else {
			form = req.URL.Query()
		}
		a := form.Get("scope")
		if !scope2.ScopesExist(a) {
			return "", errInvalidScope
		}
		return a, nil
	})

	return c
}
