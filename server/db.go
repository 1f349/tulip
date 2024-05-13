package server

import (
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/logger"
	"net/http"
)

// DbTx wraps a database transaction with http error messages and a simple action
// function. If the action function returns an error the transaction will be
// rolled back. If there is no error then the transaction is committed.
func (h *HttpServer) DbTx(rw http.ResponseWriter, action func(db *database.Queries) error) bool {
	err := action(h.db)
	if err != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		logger.Logger.Helper()
		logger.Logger.Warn("Database action error", "err", err)
		return true
	}

	return false
}
