package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeadersForBrowserToken(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"response":{"total":0,"configProfiles":[]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Forwarded: true}
	if _, err := c.ListProfiles(context.Background(), Credentials{Token: "jwt", Browser: true}); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer jwt" || got.Get("X-Remnawave-Client-Type") != "browser" {
		t.Fatalf("headers %v", got)
	}
	if got.Get("X-Forwarded-Proto") != "https" || got.Get("X-Forwarded-For") == "" {
		t.Fatalf("forwarded headers missing: %v", got)
	}
}

func TestNoClientTypeForAPIToken(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"response":{"total":0,"configProfiles":[]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, _ = c.ListProfiles(context.Background(), Credentials{Token: "api"})
	if got.Get("X-Remnawave-Client-Type") != "" {
		t.Fatal("API token must not send the browser client type")
	}
}

func TestErrorStatusIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := c.GetProfile(context.Background(), Credentials{Token: "x"}, "u")
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized {
		t.Fatalf("err %v, want *Error with 401", err)
	}
}

func TestUpdateProfileConfigBody(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/config-profiles" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"response":{}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if err := c.UpdateProfileConfig(context.Background(), Credentials{Token: "x"}, "u1", map[string]any{"a": 1.0}); err != nil {
		t.Fatal(err)
	}
	if body["uuid"] != "u1" || body["config"].(map[string]any)["a"] != 1.0 {
		t.Fatalf("body %v", body)
	}
}

func TestGetProfileParsesNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"uuid":"u1","name":"p","config":{"inbounds":[]},"nodes":[{"uuid":"n1","name":"node"}]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	p, err := c.GetProfile(context.Background(), Credentials{Token: "x"}, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "p" || len(p.NodeUUIDs) != 1 || p.NodeUUIDs[0] != "n1" || p.Config == nil {
		t.Fatalf("profile %+v", p)
	}
}

func TestGetNodeParsesState(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"response":{"uuid":"n1","address":"203.0.113.7","isConnected":true,"isDisabled":true}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	n, err := c.GetNode(context.Background(), Credentials{Token: "x"}, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/nodes/n1" {
		t.Fatalf("path %q", path)
	}
	want := Node{UUID: "n1", Address: "203.0.113.7", IsConnected: true, IsDisabled: true}
	if n != want {
		t.Fatalf("node %+v, want %+v", n, want)
	}
}

func TestCreateUser(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"response":{"id":77,"username":"alice"}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	u, err := c.CreateUser(context.Background(), Credentials{Token: "x"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != 77 || body["username"] != "alice" || body["expireAt"] == nil {
		t.Fatalf("user %+v body %v", u, body)
	}
}

func TestProfileKeepsBigIntegers(t *testing.T) {
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			sent = string(b)
		}
		_, _ = w.Write([]byte(`{"response":{"uuid":"u1","name":"p","config":{"big":9007199254740993},"nodes":[]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	p, err := c.GetProfile(context.Background(), Credentials{Token: "x"}, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateProfileConfig(context.Background(), Credentials{Token: "x"}, "u1", p.Config); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sent, "9007199254740993") {
		t.Fatalf("big integer changed: %s", sent)
	}
}

func TestListUsersPaginates(t *testing.T) {
	old := usersPageSize
	usersPageSize = 2
	defer func() { usersPageSize = old }()
	all := []string{`{"id":1,"username":"a","status":"ACTIVE"}`, `{"id":2,"username":"b","status":"DISABLED"}`, `{"id":3,"username":"c","status":"ACTIVE"}`}
	var starts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("start")
		starts = append(starts, start+"/"+r.URL.Query().Get("size"))
		page := all[2:]
		if start == "0" {
			page = all[:2]
		}
		_, _ = w.Write([]byte(`{"response":{"total":3,"users":[` + strings.Join(page, ",") + `]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	users, err := c.ListUsers(context.Background(), Credentials{Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[1].Username != "b" || users[1].Status != "DISABLED" || strings.Join(starts, ",") != "0/2,2/2" {
		t.Fatalf("users %+v, requests %v", users, starts)
	}
}
