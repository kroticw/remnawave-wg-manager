package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
)

type fakeSvc struct {
	err     error
	gotCred panel.Credentials
}

func (f *fakeSvc) Inbounds(_ context.Context, c panel.Credentials) ([]clients.InboundInfo, error) {
	f.gotCred = c
	return []clients.InboundInfo{{Profile: "p", Tag: "wg"}}, f.err
}
func (f *fakeSvc) Clients(context.Context, panel.Credentials, string, string) ([]clients.ClientInfo, error) {
	return []clients.ClientInfo{{Email: "76"}}, f.err
}
func (f *fakeSvc) Create(_ context.Context, _ panel.Credentials, _, _, user, _ string) (clients.ClientInfo, error) {
	return clients.ClientInfo{Email: "76", Username: user}, f.err
}
func (f *fakeSvc) Delete(context.Context, panel.Credentials, string, string, string) error {
	return f.err
}
func (f *fakeSvc) Config(context.Context, panel.Credentials, string, string, string) (string, error) {
	return "[Interface]\n", f.err
}

var static = fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRequiresToken(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", w.Code)
	}
}

func TestBrowserCredentials(t *testing.T) {
	svc := &fakeSvc{}
	h := New(svc, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "jwt", ""); w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	if svc.gotCred.Token != "jwt" || !svc.gotCred.Browser {
		t.Fatalf("cred %+v", svc.gotCred)
	}
}

func TestPanelUnauthorizedIsPassedThrough(t *testing.T) {
	h := New(&fakeSvc{err: &panel.Error{Status: 401}}, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "expired", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", w.Code)
	}
}

func TestStatusFor(t *testing.T) {
	cases := map[error]int{
		fmt.Errorf("x: %w", profile.ErrNotFound):   404,
		fmt.Errorf("x: %w", profile.ErrConflict):   409,
		fmt.Errorf("x: %w", profile.ErrInvalid):    400,
		fmt.Errorf("x: %w", clients.ErrNotManaged): 409,
		&panel.Error{Status: 403}:                  403,
		&panel.Error{Status: 500}:                  502,
		errors.New("boom"):                         502,
	}
	for err, want := range cases {
		if got := StatusFor(err); got != want {
			t.Errorf("%v: %d, want %d", err, got, want)
		}
	}
}

func TestCreateMapsConflict(t *testing.T) {
	h := New(&fakeSvc{err: fmt.Errorf("full: %w", profile.ErrConflict)}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodPost, "/wg/api/inbounds/p/wg/clients", "jwt", `{"user":"alice"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code %d", w.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] == "" {
		t.Fatalf("no error message: %s", w.Body)
	}
}

func TestConfigDownload(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/inbounds/p/wg/clients/76/config", "jwt", "")
	_, params, err := mime.ParseMediaType(w.Header().Get("Content-Disposition"))
	if w.Code != 200 || err != nil || params["filename"] != "wg-76.conf" {
		t.Fatalf("code %d headers %v", w.Code, w.Header())
	}
}

func TestQR(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/inbounds/p/wg/clients/76/qr.svg", "jwt", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("code %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/", "", "")
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "font-src 'self'", "img-src 'self' data: blob:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q misses %q", csp, want)
		}
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers %v", w.Header())
	}
}

func TestMetaIsPublic(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/meta", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"/auth/login"`) {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
}

func TestConfigDownloadQuotesFilename(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/inbounds/p/wg/clients/a%22b/config", "jwt", "")
	_, params, err := mime.ParseMediaType(w.Header().Get("Content-Disposition"))
	if err != nil || params["filename"] != `wg-a"b.conf` {
		t.Fatalf("Content-Disposition %q: params %v, err %v", w.Header().Get("Content-Disposition"), params, err)
	}
}
