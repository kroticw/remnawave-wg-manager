package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
)

type fakeSvc struct{ cred panel.Credentials }

func (f *fakeSvc) Inbounds(_ context.Context, c panel.Credentials) ([]clients.InboundInfo, error) {
	f.cred = c
	return []clients.InboundInfo{{Profile: "p", Tag: "wg"}}, nil
}
func (f *fakeSvc) Clients(context.Context, panel.Credentials, string, string) ([]clients.ClientInfo, error) {
	return nil, nil
}
func (f *fakeSvc) Create(context.Context, panel.Credentials, string, string, string, string) (clients.ClientInfo, error) {
	return clients.ClientInfo{Email: "76"}, nil
}
func (f *fakeSvc) Delete(context.Context, panel.Credentials, string, string, string) error {
	return nil
}
func (f *fakeSvc) Config(context.Context, panel.Credentials, string, string, string) (string, error) {
	return "[Interface]\n", nil
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestToolsAndAPITokenCredentials(t *testing.T) {
	svc := &fakeSvc{}
	srv := httptest.NewServer(Handler(svc))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{"api-token"}}}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = tool
	}
	for _, n := range []string{"wg_list_inbounds", "wg_list_clients", "wg_create_client", "wg_delete_client", "wg_get_client_config"} {
		if names[n] == nil {
			t.Fatalf("tool %s missing", n)
		}
	}
	if d := names["wg_delete_client"].Annotations.DestructiveHint; d == nil || !*d {
		t.Fatal("wg_delete_client must be destructive")
	}
	if !names["wg_list_clients"].Annotations.ReadOnlyHint {
		t.Fatal("wg_list_clients must be read-only")
	}

	if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "wg_list_inbounds", Arguments: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if svc.cred.Token != "api-token" || svc.cred.Browser {
		t.Fatalf("cred %+v, want API token without browser flag", svc.cred)
	}
}
