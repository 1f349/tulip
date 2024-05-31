package server

import (
	"errors"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/logger"
	"net/http"
)

var ErrDatabaseActionFailed = errors.New("database action failed")

// DbTx wraps a database transaction with http error messages and a simple action
// function. If the action function returns an error the transaction will be
// rolled back. If there is no error then the transaction is committed.
func (h *HttpServer) DbTx(rw http.ResponseWriter, action func(tx *database.Queries) error) bool {
	logger.Logger.Helper()
	if h.DbTxError(action) != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		return true
	}

	return false
}

func (h *HttpServer) DbTxError(action func(tx *database.Queries) error) error {
	logger.Logger.Helper()
	err := action(h.db)
	if err != nil {
		logger.Logger.Warn("Database action error", "err", err)
		return ErrDatabaseActionFailed
	}
	return nil
}
