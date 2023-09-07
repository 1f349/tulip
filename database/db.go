package database

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed init.sql
var initSql string

type DB struct{ db *sql.DB }

func Open(p string) (*DB, error) {
	db, err := sql.Open("sqlite3", p)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(initSql)
	return &DB{db: db}, err
}

func (d *DB) Begin() (*Tx, error) {
	begin, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{begin}, err
}

func (d *DB) BeginCtx(ctx context.Context) (*Tx, error) {
	begin, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{begin}, err
}

func (d *DB) Close() error {
	return d.db.Close()
}
