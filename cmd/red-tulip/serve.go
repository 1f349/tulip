package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/mail/templates"
	"github.com/1f349/tulip/red-pages"
	"github.com/1f349/tulip/red-server"
	"github.com/1f349/violet/utils"
	"github.com/MrMelon54/exit-reload"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path/filepath"
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
	log.Println("[RedTulip] Starting...")

	if s.configPath == "" {
		log.Println("[RedTulip] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[RedTulip] Error: missing config file")
		} else {
			log.Println("[RedTulip] Error: open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config red_server.Conf
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		log.Println("[RedTulip] Error: invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[RedTulip] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)
	normalLoad(config, wd)
	return subcommands.ExitSuccess
}

func normalLoad(startUp red_server.Conf, wd string) {
	signingKey, err := mjwt.NewMJwtSignerFromFileOrCreate(startUp.OtpIssuer, filepath.Join(wd, "tulip.key.pem"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[Tulip] Failed to open signing key file:", err)
	}

	db, err := database.Open(filepath.Join(wd, "red-red-tulip.db.sqlite"))
	if err != nil {
		log.Fatal("[RedTulip] Failed to open database:", err)
	}

	log.Println("[RedTulip] Checking database contains at least one user")
	if err := checkDbHasUser(db); err != nil {
		log.Fatal("[RedTulip] Failed check:", err)
	}

	if err = red_pages.LoadPages(wd); err != nil {
		log.Fatal("[RedTulip] Failed to load page templates:", err)
	}
	if err := templates.LoadMailTemplates(wd); err != nil {
		log.Fatal("[RedTulip] Failed to load mail templates:", err)
	}

	srv := red_server.NewHttpServer(startUp, db, signingKey)
	log.Printf("[RedTulip] Starting HTTP red-server on '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("HTTP", srv)

	exit_reload.ExitReload("RedTulip", func() {}, func() {
		// stop http red-server
		_ = srv.Close()
		_ = db.Close()
	})
}

func genHmacKey() []byte {
	a := make([]byte, 32)
	n, err := rand.Reader.Read(a)
	if err != nil {
		log.Fatal("[RedTulip] Failed to generate HMAC key")
	}
	if n != 32 {
		log.Fatal("[RedTulip] Failed to generate HMAC key")
	}
	return a
}

func checkDbHasUser(db *database.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()
	if err := tx.HasUser(); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_, err := tx.InsertUser("Admin", "admin", "admin", "admin@localhost", false, database.RoleAdmin, false)
			if err != nil {
				return fmt.Errorf("failed to add user: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("failed to commit transaction: %w", err)
			}
			// continue normal operation now
			return nil
		} else {
			return fmt.Errorf("failed to check if table has a user: %w", err)
		}
	}
	return nil
}
