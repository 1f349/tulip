package client_store

import (
	"context"
	"github.com/1f349/tulip/database"
	"github.com/go-oauth2/oauth2/v4"
)

type ClientStore struct {
	db *database.DB
}

var _ oauth2.ClientStore = &ClientStore{}

func New(db *database.DB) *ClientStore {
	return &ClientStore{db: db}
}

func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	tx, err := c.db.BeginCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return tx.GetClientInfo(id)
}
