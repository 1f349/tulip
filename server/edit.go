package server

import (
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/lists"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func (h *HttpServer) EditGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	var user database.User

	if h.DbTx(rw, func(tx *database.Queries) error {
		var err error
		user, err = tx.GetUser(req.Context(), auth.ID)
		if err != nil {
			return fmt.Errorf("failed to read user data: %w", err)
		}
		return nil
	}) {
		return
	}

	lNonce := uuid.NewString()
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-nonce",
		Value:    lNonce,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	pages.RenderPageTemplate(rw, "edit", map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"User":         user,
		"Nonce":        lNonce,
		"FieldPronoun": user.Pronouns.String(),
		"ListZoneInfo": lists.ListZoneInfo(),
		"ListLocale":   lists.ListLocale(),
	})
}
func (h *HttpServer) EditPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if req.ParseForm() != nil {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte("400 Bad Request\n"))
		return
	}

	var patch database.UserPatch
	errs := patch.ParseFromForm(req.Form)
	if len(errs) > 0 {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(rw, "<!DOCTYPE html>\n<html>\n<body>")
		_, _ = fmt.Fprintln(rw, "<p>400 Bad Request: Failed to parse form data, press the back button in your browser, check your inputs and try again.</p>")
		_, _ = fmt.Fprintln(rw, "<ul>")
		for _, i := range errs {
			_, _ = fmt.Fprintf(rw, "  <li>%s</li>\n", i)
		}
		_, _ = fmt.Fprintln(rw, "</ul>")
		_, _ = fmt.Fprintln(rw, "</body>\n</html>")
		return
	}
	m := database.ModifyUserParams{
		Name:      patch.Name,
		Picture:   patch.Picture,
		Website:   patch.Website,
		Pronouns:  patch.Pronouns,
		Birthdate: patch.Birthdate,
		Zoneinfo:  patch.ZoneInfo,
		Locale:    patch.Locale,
		UpdatedAt: time.Now(),
		Subject:   auth.ID,
	}
	if h.DbTx(rw, func(tx *database.Queries) error {
		if _, err := tx.ModifyUser(req.Context(), m); err != nil {
			return fmt.Errorf("failed to modify user info: %w", err)
		}
		return nil
	}) {
		return
	}
	http.Redirect(rw, req, "/edit", http.StatusFound)
}
