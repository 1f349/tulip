package server

import (
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func (h *HttpServer) Home(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	rw.Header().Set("Content-Type", "text/html")
	lNonce := uuid.NewString()
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-nonce",
		Value:    lNonce,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	if auth.IsGuest() {
		pages.RenderPageTemplate(rw, "index-guest", map[string]any{
			"ServiceName": h.conf.ServiceName,
		})
		return
	}

	var userWithName *database.User
	var hasTwoFactor bool
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		userWithName, err = tx.GetUserDisplayName(auth.ID)
		if err != nil {
			return fmt.Errorf("failed to get user display name: %w", err)
		}
		hasTwoFactor, err = tx.HasTwoFactor(auth.ID)
		if err != nil {
			return fmt.Errorf("failed to get user two factor state: %w", err)
		}
		userWithName.Role, err = tx.GetUserRole(auth.ID)
		if err != nil {
			return fmt.Errorf("failed to get user role: %w", err)
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
		"IsAdmin":     userWithName.Role,
	})
}
