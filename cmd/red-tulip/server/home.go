package server

import (
	"fmt"
	"github.com/1f349/tulip/cmd/red-tulip/pages"
	"github.com/1f349/tulip/database"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) Home(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	if auth.IsGuest() {
		pages.RenderPageTemplate(rw, "index-guest", map[string]any{
			"ServiceName": h.conf.ServiceName,
		})
		return
	}

	lNonce := uuid.NewString()
	auth.Session.Set("action-nonce", lNonce)
	if auth.Session.Save() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	var userWithName *database.User
	var hasTwoFactor bool
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		userWithName, err = tx.GetUserDisplayName(auth.Data.ID)
		if err != nil {
			return fmt.Errorf("failed to get user display name: %w", err)
		}
		hasTwoFactor, err = tx.HasTwoFactor(auth.Data.ID)
		if err != nil {
			return fmt.Errorf("failed to get user two factor state: %w", err)
		}
		return
	}) {
		return
	}
	pages.RenderPageTemplate(rw, "index", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Auth":        auth,
		"User":        userWithName,
		"Nonce":       lNonce,
		"OtpEnabled":  hasTwoFactor,
	})
}
