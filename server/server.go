package server

import (
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/json"
	errors2 "errors"
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/lists"
	"github.com/1f349/tulip/openid"
	"github.com/1f349/tulip/pages"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"time"
)

var errMissingRequiredScope = errors.New("missing required scope")

type HttpServer struct {
	r        *httprouter.Router
	oauthSrv *server.Server
	oauthMgr *manage.Manager
	db       *database.DB
	domain   string
	privKey  []byte
}

func NewHttpServer(listen, domain string, db *database.DB, privKey []byte, clientStore oauth2.ClientStore) *http.Server {
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
		r:        httprouter.New(),
		oauthSrv: oauthSrv,
		oauthMgr: oauthManager,
		db:       db,
		domain:   domain,
		privKey:  privKey,
	}

	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(generates.NewAccessGenerate())
	oauthManager.MapClientStorage(clientStore)

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
	r.GET("/", hs.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		if auth.IsGuest() {
			_ = pages.RenderPageTemplate(rw, "index-guest", nil)
			return
		}

		lNonce := uuid.NewString()
		auth.Session.Set("action-nonce", lNonce)
		if auth.Session.Save() != nil {
			http.Error(rw, "Failed to save session", http.StatusInternalServerError)
			return
		}

		var userWithName *database.User
		if hs.DbTx(rw, func(tx *database.Tx) (err error) {
			userWithName, err = tx.GetUserDisplayName(auth.ID)
			if err != nil {
				return fmt.Errorf("failed to get user display name: %w", err)
			}
			return
		}) {
			return
		}
		if err := pages.RenderPageTemplate(rw, "index", map[string]any{
			"Auth":  auth,
			"User":  userWithName,
			"Nonce": lNonce,
		}); err != nil {
			log.Printf("Failed to render page: edit: %s\n", err)
		}
	}))
	r.POST("/logout", hs.RequireAuthentication("403 Forbidden", http.StatusForbidden, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		lNonce, ok := auth.Session.Get("action-nonce")
		if !ok {
			http.Error(rw, "Missing nonce", http.StatusInternalServerError)
			return
		}
		if subtle.ConstantTimeCompare([]byte(lNonce.(string)), []byte(req.PostFormValue("nonce"))) == 1 {
			auth.Session.Delete("user")
			if auth.Session.Save() != nil {
				http.Error(rw, "Failed to save session", http.StatusInternalServerError)
				return
			}
			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Logout failed", http.StatusInternalServerError)
	}))
	r.GET("/login", hs.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if !auth.IsGuest() {
			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		if err := pages.RenderPageTemplate(rw, "login", nil); err != nil {
			log.Printf("Failed to render page: edit: %s\n", err)
		}
	}))
	r.POST("/login", hs.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		un := req.FormValue("username")
		pw := req.FormValue("password")
		var userSub uuid.UUID
		if hs.DbTx(rw, func(tx *database.Tx) error {
			loginUser, err := tx.CheckLogin(un, pw)
			if err != nil {
				if errors2.Is(err, sql.ErrNoRows) || errors2.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
					http.Redirect(rw, req, "/login?mismatch=1", http.StatusFound)
					return nil
				}
				http.Error(rw, "Internal server error", http.StatusInternalServerError)
				return err
			}
			userSub = loginUser.Sub
			return nil
		}) {
			return
		}

		// only continues if the above tx succeeds
		auth.Session.Set("user", userSub)
		if auth.Session.Save() != nil {
			http.Error(rw, "Failed to save session", http.StatusInternalServerError)
			return
		}

		switch req.URL.Query().Get("redirect") {
		case "oauth":
			oauthDataRaw, ok := auth.Session.Get("OAuthData")
			if !ok {
				http.Error(rw, "Failed to load session", http.StatusInternalServerError)
				return
			}
			oauthData, ok := oauthDataRaw.(url.Values)
			if !ok {
				http.Error(rw, "Failed to load session", http.StatusInternalServerError)
				return
			}
			authUrl := url.URL{Path: "/authorize", RawQuery: oauthData.Encode()}
			http.Redirect(rw, req, authUrl.String(), http.StatusFound)
		default:
			http.Redirect(rw, req, "/", http.StatusFound)
		}
	}))
	r.GET("/authorize", hs.authorizeEndpoint)
	r.POST("/authorize", hs.authorizeEndpoint)
	r.POST("/token", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if err := oauthSrv.HandleTokenRequest(rw, req); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})
	r.GET("/edit", hs.RequireAuthentication("403 Forbidden", http.StatusForbidden, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		var user *database.User

		if hs.DbTx(rw, func(tx *database.Tx) error {
			var err error
			user, err = tx.GetUser(auth.ID)
			if err != nil {
				return fmt.Errorf("failed to read user data: %w", err)
			}
			return nil
		}) {
			return
		}

		lNonce := uuid.NewString()
		auth.Session.Set("action-nonce", lNonce)
		if auth.Session.Save() != nil {
			http.Error(rw, "Failed to save session", http.StatusInternalServerError)
			return
		}
		if err := pages.RenderPageTemplate(rw, "edit", map[string]any{
			"User":         user,
			"Nonce":        lNonce,
			"ListZoneInfo": lists.ListZoneInfo(),
			"ListLocale":   lists.ListLocale(),
		}); err != nil {
			log.Printf("Failed to render page: edit: %s\n", err)
		}
	}))
	r.POST("/edit", hs.RequireAuthentication("403 Forbidden", http.StatusForbidden, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if req.ParseForm() != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		var patch database.UserPatch
		err := patch.ParseFromForm(req.Form)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		if hs.DbTx(rw, func(tx *database.Tx) error {
			if err := tx.ModifyUser(auth.ID, &patch); err != nil {
				return fmt.Errorf("failed to modify user info: %w", err)
			}
			return nil
		}) {
			return
		}
		http.Redirect(rw, req, "/", http.StatusFound)
	}))
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
