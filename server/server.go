package server

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	clientStore "github.com/1f349/tulip/client-store"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/openid"
	"github.com/1f349/tulip/pages"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"net/url"
	"time"
)

var errMissingRequiredScope = errors.New("missing required scope")

type HttpServer struct {
	r           *httprouter.Router
	oauthSrv    *server.Server
	oauthMgr    *manage.Manager
	db          *database.DB
	domain      string
	privKey     []byte
	otpIssuer   string
	serviceName string
}

func (h *HttpServer) SafeRedirect(rw http.ResponseWriter, req *http.Request) {
	redirectUrl := req.FormValue("redirect")
	if redirectUrl == "" {
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}
	parse, err := url.Parse(redirectUrl)
	if err != nil {
		http.Error(rw, "Failed to parse redirect url: "+redirectUrl, http.StatusBadRequest)
		return
	}
	if parse.Scheme != "" && parse.Opaque != "" && parse.User != nil && parse.Host != "" {
		http.Error(rw, "Invalid redirect url: "+redirectUrl, http.StatusBadRequest)
		return
	}
	http.Redirect(rw, req, parse.String(), http.StatusFound)
}

func NewHttpServer(listen, domain, otpIssuer, serviceName string, db *database.DB, privKey []byte) *http.Server {
	r := httprouter.New()

	openIdConf := openid.GenConfig(domain, []string{"openid", "email"}, []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at"})
	openIdBytes, err := json.Marshal(openIdConf)
	if err != nil {
		log.Fatalln("Failed to generate OpenID configuration:", err)
	}

	if err := pages.LoadPageTemplates(); err != nil {
		log.Fatalln("Failed to load page templates:", err)
	}

	oauthManager := manage.NewDefaultManager()
	oauthSrv := server.NewServer(server.NewConfig(), oauthManager)
	hs := &HttpServer{
		r:           httprouter.New(),
		oauthSrv:    oauthSrv,
		oauthMgr:    oauthManager,
		db:          db,
		domain:      domain,
		privKey:     privKey,
		otpIssuer:   otpIssuer,
		serviceName: serviceName,
	}

	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(generates.NewAccessGenerate())
	oauthManager.MapClientStorage(clientStore.New(db))

	oauthSrv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Printf("Response error: %#v\n", re)
	})
	oauthSrv.SetClientInfoHandler(func(req *http.Request) (clientID, clientSecret string, err error) {
		cId, cSecret, err := server.ClientBasicHandler(req)
		if cId == "" && cSecret == "" {
			cId, cSecret, err = server.ClientFormHandler(req)
		}
		if err != nil {
			return "", "", err
		}
		return cId, cSecret, nil
	})
	oauthSrv.SetUserAuthorizationHandler(hs.oauthUserAuthorization)
	oauthSrv.SetAuthorizeScopeHandler(func(rw http.ResponseWriter, req *http.Request) (scope string, err error) {
		var form url.Values
		if req.Method == http.MethodPost {
			form = req.PostForm
		} else {
			form = req.URL.Query()
		}
		a := form.Get("scope")
		if a != "openid" {
			return "", errMissingRequiredScope
		}
		return "openid", nil
	})

	r.GET("/.well-known/openid-configuration", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(openIdBytes)
	})
	r.GET("/", OptionalAuthentication(false, hs.Home))
	r.POST("/logout", RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		lNonce, ok := auth.Session.Get("action-nonce")
		if !ok {
			http.Error(rw, "Missing nonce", http.StatusInternalServerError)
			return
		}
		if subtle.ConstantTimeCompare([]byte(lNonce.(string)), []byte(req.PostFormValue("nonce"))) == 1 {
			auth.Session.Delete("session-data")
			if auth.Session.Save() != nil {
				http.Error(rw, "Failed to save session", http.StatusInternalServerError)
				return
			}
			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Logout failed", http.StatusInternalServerError)
	}))

	// login steps
	r.GET("/login", OptionalAuthentication(false, hs.LoginGet))
	r.POST("/login", OptionalAuthentication(false, hs.LoginPost))
	r.GET("/login/otp", OptionalAuthentication(true, hs.LoginOtpGet))
	r.POST("/login/otp", OptionalAuthentication(true, hs.LoginOtpPost))

	// edit profile pages
	r.GET("/edit", RequireAuthentication(hs.EditGet))
	r.POST("/edit", RequireAuthentication(hs.EditPost))
	r.GET("/edit/otp", RequireAuthentication(hs.EditOtpGet))
	r.POST("/edit/otp", RequireAuthentication(hs.EditOtpPost))

	// management pages
	r.GET("/manage/apps", hs.RequireAdminAuthentication(hs.ManageAppsGet))
	r.POST("/manage/apps", hs.RequireAdminAuthentication(hs.ManageAppsPost))
	r.GET("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersGet))
	r.POST("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersPost))

	// oauth pages
	r.GET("/authorize", RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/authorize", RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/token", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if err := oauthSrv.HandleTokenRequest(rw, req); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})
	r.GET("/userinfo", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		token, err := oauthSrv.ValidationBearerToken(req)
		if err != nil {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		fmt.Printf("Using token for user: %s by app: %s with scope: '%s'\n", token.GetUserID(), token.GetClientID(), token.GetScope())
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"sub":                token.GetUserID(),
			"aud":                token.GetClientID(),
			"name":               "Melon",
			"preferred_username": "melon",
			"profile":            "https://" + domain + "/user/melon",
			"picture":            "https://" + domain + "/picture/melon.svg",
			"website":            "https://mrmelon54.com",
			"email":              "melon@mrmelon54.com",
			"email_verified":     true,
			"gender":             "male",
			"birthdate":          time.Now().Format(time.DateOnly),
			"zoneinfo":           "Europe/London",
			"locale":             "en-GB",
			"updated_at":         time.Now().Unix(),
		})
	})

	return &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
}
