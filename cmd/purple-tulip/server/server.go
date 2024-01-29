package server

import (
	"bytes"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/mjwt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/issuer"
	"github.com/1f349/tulip/oauth"
	"github.com/1f349/tulip/theme"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type HttpServer struct {
	Server    *http.Server
	r         *httprouter.Router
	conf      atomic.Pointer[Conf]
	manager   atomic.Pointer[issuer.Manager]
	signer    mjwt.Signer
	flowState *cache.Cache[string, flowStateData]
	services  atomic.Pointer[map[string]AllowedClient]
}

type flowStateData struct {
	sso    *issuer.WellKnownOIDC
	target AllowedClient
}

func NewHttpServer(conf Conf, db *database.DB, controller *oauth.Controller, signer mjwt.Signer) *HttpServer {
	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(conf.BaseUrl)
		if conf.BaseUrl[l-1] == '/' {
			conf.BaseUrl = conf.BaseUrl[:l-1]
		}
	}

	hs := &HttpServer{
		Server: &http.Server{
			Addr:              conf.Listen,
			Handler:           r,
			ReadTimeout:       time.Minute,
			ReadHeaderTimeout: time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    2500,
		},
		r:         r,
		signer:    signer,
		flowState: cache.New[string, flowStateData](),
	}
	err := hs.UpdateConfig(conf)
	if err != nil {
		log.Fatalln("Failed to load initial config:", err)
		return nil
	}

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(rw, "What is this?")
	})
	r.GET("/popup", hs.flowPopup)
	r.POST("/popup", hs.flowPopupPost)
	r.GET("/callback", hs.flowCallback)

	r.GET("/theme/style.css", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.ServeContent(rw, req, "style.css", time.Now(), bytes.NewReader(theme.DefaultThemeCss))
	})

	// setup CORS options for `/verify` and `/refresh` endpoints
	var corsAccessControl = cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			load := hs.services.Load()
			_, ok := (*load)[strings.TrimSuffix(origin, "/")]
			return ok
		},
		AllowedMethods:   []string{http.MethodPost, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})

	// `/verify` and `/refresh` need CORS headers to be usable on other domains
	r.POST("/verify", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		corsAccessControl.ServeHTTP(rw, req, func(writer http.ResponseWriter, request *http.Request) {
			hs.verifyHandler(rw, req, params)
		})
	})
	r.POST("/refresh", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		corsAccessControl.ServeHTTP(rw, req, func(writer http.ResponseWriter, request *http.Request) {
			hs.refreshHandler(rw, req, params)
		})
	})
	r.OPTIONS("/refresh", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		corsAccessControl.ServeHTTP(rw, req, func(_ http.ResponseWriter, _ *http.Request) {})
	})
	return hs
}

func (h *HttpServer) UpdateConfig(conf Conf) error {
	m, err := issuer.NewManager(conf.SsoServices)
	if err != nil {
		return fmt.Errorf("failed to reload SSO service manager: %w", err)
	}

	clientLookup := make(map[string]AllowedClient)
	for _, i := range conf.AllowedClients {
		clientLookup[i.Url.String()] = i
	}

	h.conf.Store(&conf)
	h.manager.Store(m)
	h.services.Store(&clientLookup)
	return nil
}
