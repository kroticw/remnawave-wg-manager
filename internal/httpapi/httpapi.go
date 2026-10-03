// Package httpapi serves the REST API and the static page.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"strings"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
	"github.com/kroticw/remnawave-wg-manager/internal/wgconf"
)

// blob: lets the page show the QR code fetched with the Authorization header.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// Service is the set of client operations the API exposes.
type Service interface {
	Inbounds(ctx context.Context, cred panel.Credentials) ([]clients.InboundInfo, error)
	Clients(ctx context.Context, cred panel.Credentials, profile, tag string) ([]clients.ClientInfo, error)
	Create(ctx context.Context, cred panel.Credentials, profile, tag, user, address string) (clients.ClientInfo, error)
	Delete(ctx context.Context, cred panel.Credentials, profile, tag, email string) error
	Config(ctx context.Context, cred panel.Credentials, profile, tag, email string) (string, error)
}

// SecurityHeaders sets CSP and related headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// StatusFor maps an operation error to an HTTP status.
func StatusFor(err error) int {
	var pe *panel.Error
	switch {
	case errors.As(err, &pe) && (pe.Status == http.StatusUnauthorized || pe.Status == http.StatusForbidden):
		return pe.Status
	case errors.As(err, &pe) && pe.Status == http.StatusNotFound:
		return http.StatusNotFound
	case errors.Is(err, profile.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, profile.ErrConflict), errors.Is(err, clients.ErrNotManaged):
		return http.StatusConflict
	case errors.Is(err, profile.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, StatusFor(err), map[string]string{"error": err.Error()})
}

func credentials(r *http.Request) (panel.Credentials, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return panel.Credentials{}, false
	}
	return panel.Credentials{Token: token, Browser: true}, true
}

func authed(fn func(http.ResponseWriter, *http.Request, panel.Credentials)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, ok := credentials(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}
		fn(w, r, cred)
	}
}

// New returns the handler for the page and the REST API under basePath.
func New(svc Service, basePath, loginPath string, static fs.FS) http.Handler {
	mux := http.NewServeMux()
	b := strings.TrimSuffix(basePath, "/")

	mux.Handle("GET "+b+"/", http.StripPrefix(b+"/", http.FileServerFS(static)))
	mux.HandleFunc("GET "+b+"/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET "+b+"/api/meta", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"loginPath": loginPath})
	})
	mux.HandleFunc("GET "+b+"/api/inbounds", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		list, err := svc.Inbounds(r.Context(), c)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}))
	const clientsPath = "/api/inbounds/{profile}/{tag}/clients"
	mux.HandleFunc("GET "+b+clientsPath, authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		list, err := svc.Clients(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}))
	mux.HandleFunc("POST "+b+clientsPath, authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		var req struct {
			User    string `json:"user"`
			Address string `json:"address"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		ci, err := svc.Create(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), req.User, req.Address)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, ci)
	}))
	mux.HandleFunc("DELETE "+b+clientsPath+"/{email}", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		if err := svc.Delete(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email")); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET "+b+clientsPath+"/{email}/config", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		conf, err := svc.Config(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email"))
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "wg-" + r.PathValue("email") + ".conf"}))
		// Plain text served as an attachment with nosniff; it is never rendered as HTML.
		_, _ = w.Write([]byte(conf)) //nolint:gosec // G705: see above
	}))
	mux.HandleFunc("GET "+b+clientsPath+"/{email}/qr.svg", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		conf, err := svc.Config(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email"))
		if err != nil {
			writeErr(w, err)
			return
		}
		svg, err := wgconf.QRSVG(conf)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-store")
		// The SVG is generated from the QR matrix only; no request data reaches it as markup.
		_, _ = w.Write([]byte(svg)) //nolint:gosec // G705: see above
	}))
	return SecurityHeaders(mux)
}
