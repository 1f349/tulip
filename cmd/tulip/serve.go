package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/tulip"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/database/types"
	"github.com/1f349/tulip/mail/templates"
	"github.com/1f349/tulip/pages"
	"github.com/1f349/tulip/server"
	"github.com/1f349/violet/utils"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mrmelon54/exit-reload"
	"log"
	"os"
	"path/filepath"
	"time"
)

type serveCmd struct{ configPath string }

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve user authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>]
  Serve user authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	log.Println("[Tulip] Starting...")

	if s.configPath == "" {
		log.Println("[Tulip] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[Tulip] Error: missing config file")
		} else {
			log.Println("[Tulip] Error: open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config server.Conf
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		log.Println("[Tulip] Error: invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[Tulip] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)
	normalLoad(config, wd)
	return subcommands.ExitSuccess
}

func normalLoad(startUp server.Conf, wd string) {
	signingKey, err := mjwt.NewMJwtSignerFromFileOrCreate(startUp.OtpIssuer, filepath.Join(wd, "tulip.key.pem"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[Tulip] Failed to open signing key file:", err)
	}

	db, err := tulip.InitDB(filepath.Join(wd, "tulip.db.sqlite"))
	if err != nil {
		log.Fatal("[Tulip] Failed to open database:", err)
	}

	log.Println("[Tulip] Checking database contains at least one user")
	if err := checkDbHasUser(db); err != nil {
		log.Fatal("[Tulip] Failed check:", err)
	}

	if err = pages.LoadPages(wd); err != nil {
		log.Fatal("[Tulip] Failed to load page templates:", err)
	}
	if err := templates.LoadMailTemplates(wd); err != nil {
		log.Fatal("[Tulip] Failed to load mail templates:", err)
	}

	srv := server.NewHttpServer(startUp, db, signingKey)
	log.Printf("[Tulip] Starting HTTP server on '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("HTTP", srv)

	exit_reload.ExitReload("Tulip", func() {}, func() {
		// stop http server
		_ = srv.Close()
	})
}

func checkDbHasUser(db *database.Queries) error {
	value, err := db.HasUser(context.Background())
	if err != nil {
		return err
	}

	if !value {
		_, err := db.AddUser(context.Background(), database.AddUserParams{
			Name:          "Admin",
			Username:      "admin",
			Password:      "admin",
			Email:         "admin@localhost",
			EmailVerified: false,
			Role:          types.RoleAdmin,
			UpdatedAt:     time.Now(),
			Active:        false,
		})
		if err != nil {
			return fmt.Errorf("failed to add user: %w", err)
		}
		// continue normal operation now
	}
	return nil
}
