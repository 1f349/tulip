package server

import (
	"github.com/1f349/tulip/database"
	"log"
	"net/http"
)

func (h *HttpServer) dbTx(rw http.ResponseWriter, action func(tx *database.Tx) error) bool {
	tx, err := h.db.Begin()
	if err != nil {
		http.Error(rw, "Failed to begin database transaction", http.StatusInternalServerError)
		return true
	}
	defer tx.Rollback()

	err = action(tx)
	if err != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		log.Println("Database action error:", err)
		return true
	}
	err = tx.Commit()
	if err != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		log.Println("Database commit error:", err)
	}

	return false
}
