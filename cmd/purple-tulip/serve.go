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
	"github.com/1f349/tulip/purple-server"
	"github.com/1f349/tulip/purple-server/pages"
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
	log.Println("[Lavender] Starting...")

	if s.configPath == "" {
		log.Println("[Lavender] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	var conf server.Conf
	err := loadConfig(s.configPath, &conf)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[Lavender] Error: missing config file")
		} else {
			log.Println("[Lavender] Error: loading config file: ", err)
		}
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[Lavender] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)

	mSign, err := mjwt.NewMJwtSignerFromFileOrCreate(conf.Issuer, filepath.Join(wd, "lavender.private.key"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[Lavender] Failed to load or create MJWT signer:", err)
	}
	saveMjwtPubKey(mSign, wd)

	if err := pages.LoadPages(wd); err != nil {
		log.Fatal("[Lavender] Failed to load page templates:", err)
	}

	srv := server.NewHttpServer(conf, mSign)
	log.Printf("[Lavender] Starting HTTP red-server on '%s'\n", srv.Server.Addr)
	go utils.RunBackgroundHttp("HTTP", srv.Server)

	exitReload.ExitReload("Lavender", func() {
		var conf server.Conf
		err := loadConfig(s.configPath, &conf)
		if err != nil {
			log.Println("[Lavender] Failed to read config:", err)
		}
		err = srv.UpdateConfig(conf)
		if err != nil {
			log.Println("[Lavender] Failed to reload config:", err)
		}
	}, func() {
		// stop http red-server
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
		log.Fatal("[Lavender] Failed to encode MJWT public key:", err)
	}
	err = os.WriteFile(filepath.Join(wd, "lavender.public.key"), b.Bytes(), 0600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Fatal("[Lavender] Failed to save MJWT public key:", err)
	}
}
