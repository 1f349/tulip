package client_store

import (
	"context"
	"github.com/1f349/tulip/database"
	"github.com/go-oauth2/oauth2/v4"
)

type ClientStore struct {
	db *database.Queries
}

var _ oauth2.ClientStore = &ClientStore{}

func New(db *database.Queries) *ClientStore {
	return &ClientStore{db: db}
}

func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	a, err := c.db.GetClientInfo(ctx, id)
	return &a, err
}
