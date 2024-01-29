package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"github.com/1f349/mjwt"
	clientStore "github.com/1f349/tulip/client-store"
	"github.com/1f349/tulip/cmd/purple-tulip/pages"
	"github.com/1f349/tulip/cmd/purple-tulip/server"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/oauth"
	"github.com/1f349/tulip/openid"
	"github.com/1f349/violet/utils"
	exitReload "github.com/MrMelon54/exit-reload"
	"github.com/google/subcommands"
	"log"
	"os"
	"path/filepath"
)

type serveCmd struct{ configPath string }

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve API authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>]
  Serve API authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	log.Println("[PurpleTulip] Starting...")

	if s.configPath == "" {
		log.Println("[PurpleTulip] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	var conf server.Conf
	err := loadConfig(s.configPath, &conf)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[PurpleTulip] Error: missing config file")
		} else {
			log.Println("[PurpleTulip] Error: loading config file: ", err)
		}
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[PurpleTulip] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)

	signer, err := mjwt.NewMJwtSignerFromFileOrCreate(conf.Issuer, filepath.Join(wd, "purple-tulip.private.key.pem"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[PurpleTulip] Failed to load or create MJWT signer:", err)
	}
	saveMjwtPubKey(signer, wd)

	db, err := database.Open(filepath.Join(wd, "purple-tulip.db.sqlite"))
	if err != nil {
		log.Fatal("[PurpleTulip] Failed to open database:", err)
	}

	if err := pages.LoadPages(wd); err != nil {
		log.Fatal("[PurpleTulip] Failed to load page templates:", err)
	}

	openIdConf := openid.GenConfig(conf.BaseUrl, []string{"openid", "name", "username", "profile", "email", "birthdate", "age", "zoneinfo", "locale"}, []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at"})
	controller := oauth.NewOAuthController(signer, &server.PurpleAuthSource{DB: db}, clientStore.New(db), openIdConf)

	srv := server.server.NewHttpServer(conf, db, controller, signer)
	log.Printf("[PurpleTulip] Starting HTTP server on '%s'\n", srv.Server.Addr)
	go utils.RunBackgroundHttp("HTTP", srv.Server)

	exitReload.ExitReload("PurpleTulip", func() {
		var conf server.Conf
		err := loadConfig(s.configPath, &conf)
		if err != nil {
			log.Println("[PurpleTulip] Failed to read config:", err)
		}
		err = srv.UpdateConfig(conf)
		if err != nil {
			log.Println("[PurpleTulip] Failed to reload config:", err)
		}
	}, func() {
		// stop http server
		_ = srv.Server.Close()
	})

	return subcommands.ExitSuccess
}

func loadConfig(configPath string, conf *server.Conf) error {
	openConf, err := os.Open(configPath)
	if err != nil {
		return err
	}

	return json.NewDecoder(openConf).Decode(conf)
}

func saveMjwtPubKey(mSign mjwt.Signer, wd string) {
	pubKey := x509.MarshalPKCS1PublicKey(mSign.PublicKey())
	b := new(bytes.Buffer)
	err := pem.Encode(b, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKey})
	if err != nil {
		log.Fatal("[PurpleTulip] Failed to encode MJWT public key:", err)
	}
	err = os.WriteFile(filepath.Join(wd, "lavender.public.key"), b.Bytes(), 0600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Fatal("[PurpleTulip] Failed to save MJWT public key:", err)
	}
}
