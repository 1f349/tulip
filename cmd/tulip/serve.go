package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/server"
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

	var config startUpConfig
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

func normalLoad(startUp startUpConfig, wd string) {
	key := genHmacKey()

	db, err := database.Open(filepath.Join(wd, "tulip.db.sqlite"))
	if err != nil {
		log.Fatal("[Tulip] Failed to open database:", err)
	}

	log.Println("[Tulip] Checking database contains at least one user")
	if err := checkDbHasUser(db); err != nil {
		log.Fatal("[Tulip] Failed check:", err)
	}

	srv := server.NewHttpServer(startUp.Listen, startUp.Domain, startUp.OtpIssuer, startUp.ServiceName, db, key)
	log.Printf("[Tulip] Starting HTTP server on '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("HTTP", srv)

	exit_reload.ExitReload("Tulip", func() {}, func() {
		// stop http server
		_ = srv.Close()
		_ = db.Close()
	})
}

func genHmacKey() []byte {
	a := make([]byte, 32)
	n, err := rand.Reader.Read(a)
	if err != nil {
		log.Fatal("[Tulip] Failed to generate HMAC key")
	}
	if n != 32 {
		log.Fatal("[Tulip] Failed to generate HMAC key")
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
			err := tx.InsertUser("Admin", "admin", "admin", "admin@localhost", database.RoleAdmin, false)
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
