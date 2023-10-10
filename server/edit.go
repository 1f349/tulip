package server

import (
	"fmt"
	"github.com/1f349/tulip/database"
	"github.com/1f349/tulip/lists"
	"github.com/1f349/tulip/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) EditGet(rw http.ResponseWriter, _ *http.Request, _ httprouter.Params, auth UserAuth) {
	var user *database.User

	if h.DbTx(rw, func(tx *database.Tx) error {
		var err error
		user, err = tx.GetUser(auth.Data.ID)
		if err != nil {
			return fmt.Errorf("failed to read user data: %w", err)
		}
		return nil
	}) {
		return
	}

	lNonce := uuid.NewString()
	auth.Session.Set("action-nonce", lNonce)
	if auth.Session.Save() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}
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
	if h.DbTx(rw, func(tx *database.Tx) error {
		if err := tx.ModifyUser(auth.Data.ID, &patch); err != nil {
			return fmt.Errorf("failed to modify user info: %w", err)
		}
		return nil
	}) {
		return
	}
	http.Redirect(rw, req, "/edit", http.StatusFound)
}
