package server

import (
	"bytes"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/mjwt"
	clientStore "github.com/1f349/tulip/client-store"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/openid"
	scope2 "github.com/1f349/tulip/scope"
	"github.com/1f349/tulip/theme"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errInvalidScope = errors.New("missing required scope")

type HttpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.DB
	conf       Conf
	signingKey mjwt.Signer

	// mailLinkCache contains a mapping of verify uuids to user uuids
	mailLinkCache *cache.Cache[mailLinkKey, string]
}

const (
	mailLinkDelete byte = iota
	mailLinkResetPassword
	mailLinkVerifyEmail
)

type mailLinkKey struct {
	action byte
	data   string
}

func NewHttpServer(conf Conf, db *database.DB, signingKey mjwt.Signer) *http.Server {
	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(conf.BaseUrl)
		if conf.BaseUrl[l-1] == '/' {
			conf.BaseUrl = conf.BaseUrl[:l-1]
		}
	}

	openIdConf := openid.GenConfig(conf.BaseUrl, []string{"openid", "name", "username", "profile", "email", "birthdate", "age", "zoneinfo", "locale"}, []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at"})
	openIdBytes, err := json.Marshal(openIdConf)
	if err != nil {
		log.Fatalln("Failed to generate OpenID configuration:", err)
	}

	oauthManager := manage.NewDefaultManager()
	oauthSrv := server.NewServer(server.NewConfig(), oauthManager)
	hs := &HttpServer{
		r:          httprouter.New(),
		oauthSrv:   oauthSrv,
		oauthMgr:   oauthManager,
		db:         db,
		conf:       conf,
		signingKey: signingKey,

		mailLinkCache: cache.New[mailLinkKey, string](),
	}

	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(NewJWTAccessGenerate(hs.signingKey))
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
		if !scope2.ScopesExist(a) {
			return "", errInvalidScope
		}
		return a, nil
	})
	addIdTokenSupport(oauthSrv, db, signingKey)

	r.GET("/.well-known/openid-configuration", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(openIdBytes)
	})
	r.GET("/", hs.OptionalAuthentication(false, hs.Home))
	r.POST("/logout", hs.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		cookie, err := req.Cookie("tulip-nonce")
		if err != nil {
			http.Error(rw, "Missing nonce", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(req.PostFormValue("nonce"))) == 1 {
			http.SetCookie(rw, &http.Cookie{
				Name:     "tulip-login-data",
				Path:     "/",
				MaxAge:   -1,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Logout failed", http.StatusInternalServerError)
	}))

	// theme styles
	r.GET("/theme/style.css", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.ServeContent(rw, req, "style.css", time.Now(), bytes.NewReader(theme.DefaultThemeCss))
	})

	// login steps
	r.GET("/login", hs.OptionalAuthentication(false, hs.LoginGet))
	r.POST("/login", hs.OptionalAuthentication(false, hs.LoginPost))
	r.GET("/login/otp", hs.OptionalAuthentication(true, hs.LoginOtpGet))
	r.POST("/login/otp", hs.OptionalAuthentication(true, hs.LoginOtpPost))

	// mail codes
	r.GET("/mail/verify/:code", hs.MailVerify)
	r.GET("/mail/password/:code", hs.MailPassword)
	r.POST("/mail/password", hs.MailPasswordPost)
	r.GET("/mail/delete/:code", hs.MailDelete)

	// edit profile pages
	r.GET("/edit", hs.RequireAuthentication(hs.EditGet))
	r.POST("/edit", hs.RequireAuthentication(hs.EditPost))
	r.POST("/edit/otp", hs.RequireAuthentication(hs.EditOtpPost))

	// management pages
	r.GET("/manage/apps", hs.RequireAuthentication(hs.ManageAppsGet))
	r.POST("/manage/apps", hs.RequireAuthentication(hs.ManageAppsPost))
	r.GET("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersGet))
	r.POST("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersPost))

	// oauth pages
	r.GET("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
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
		userId := token.GetUserID()

		fmt.Printf("Using token for user: %s by app: %s with scope: '%s'\n", userId, token.GetClientID(), token.GetScope())
		claims := ParseClaims(token.GetScope())
		if !claims["openid"] {
			http.Error(rw, "Invalid scope", http.StatusBadRequest)
			return
		}

		var userData *database.User

		if hs.DbTx(rw, func(tx *database.Tx) (err error) {
			userData, err = tx.GetUser(userId)
			return err
		}) {
			return
		}

		m := map[string]any{}
		m["sub"] = userId
		m["aud"] = token.GetClientID()
		if claims["name"] {
			m["name"] = userData.Name
		}
		if claims["username"] {
			m["preferred_username"] = userData.Username
			m["login"] = userData.Username
		}
		if claims["profile"] {
			m["profile"] = conf.BaseUrl + "/user/" + userData.Username
			m["picture"] = userData.Picture.String()
			m["website"] = userData.Website.String()
		}
		if claims["email"] {
			m["email"] = userData.Email
			m["email_verified"] = userData.EmailVerified
		}
		if claims["birthdate"] {
			m["birthdate"] = userData.Birthdate.String()
		}
		if claims["age"] {
			m["age"] = CalculateAge(userData.Birthdate.Time.In(userData.ZoneInfo.Location))
		}
		if claims["zoneinfo"] {
			m["zoneinfo"] = userData.ZoneInfo.Location.String()
		}
		if claims["locale"] {
			m["locale"] = userData.Locale.Tag.String()
		}
		m["updated_at"] = time.Now().Unix()

		_ = json.NewEncoder(rw).Encode(m)
	})

	return &http.Server{
		Addr:              conf.Listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
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

func ParseClaims(claims string) map[string]bool {
	m := make(map[string]bool)
	for {
		n := strings.IndexByte(claims, ' ')
		if n == -1 {
			if claims != "" {
				m[claims] = true
			}
			break
		}

		a := claims[:n]
		claims = claims[n+1:]
		if a != "" {
			m[a] = true
		}
	}

	return m
}

var ageTimeNow = func() time.Time { return time.Now() }

func CalculateAge(t time.Time) int {
	n := ageTimeNow()

	// the birthday is in the future so the age is 0
	if n.Before(t) {
		return 0
	}

	// the year difference
	dy := n.Year() - t.Year()

	// the birthday in the current year
	tCurrent := t.AddDate(dy, 0, 0)

	// minus 1 if the birthday has not yet occurred in the current year
	if tCurrent.Before(n) {
		dy -= 1
	}
	return dy
}
