// Package panel is a minimal client for the Remnawave panel API.
package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// farFuture is the expiry given to panel users created for WireGuard clients.
const farFuture = "2099-01-01T00:00:00.000Z"

// Credentials authenticate a request to the panel. Browser marks an admin
// session JWT, which the panel accepts only with the browser client type.
type Credentials struct {
	Token   string
	Browser bool
}

// Error is a non-2xx response of the panel.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("panel responded %d: %s", e.Status, e.Body)
}

// Profile is a config profile with its Xray configuration and nodes.
type Profile struct {
	UUID      string
	Name      string
	Config    map[string]any
	NodeUUIDs []string
}

// User is a panel user.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// Client calls the panel API.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	Forwarded bool
}

type rawProfile struct {
	UUID   string         `json:"uuid"`
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
	Nodes  []struct {
		UUID string `json:"uuid"`
	} `json:"nodes"`
}

func (r rawProfile) profile() Profile {
	p := Profile{UUID: r.UUID, Name: r.Name, Config: r.Config}
	for _, n := range r.Nodes {
		p.NodeUUIDs = append(p.NodeUUIDs, n.UUID)
	}
	return p
}

func (c *Client) do(ctx context.Context, cred Credentials, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cred.Token)
	req.Header.Set("Content-Type", "application/json")
	if cred.Browser {
		req.Header.Set("X-Remnawave-Client-Type", "browser")
	}
	if c.Forwarded {
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	var env struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if err := json.Unmarshal(env.Response, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// ListProfiles returns all config profiles.
func (c *Client) ListProfiles(ctx context.Context, cred Credentials) ([]Profile, error) {
	var r struct {
		ConfigProfiles []rawProfile `json:"configProfiles"`
	}
	if err := c.do(ctx, cred, http.MethodGet, "/api/config-profiles", nil, &r); err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(r.ConfigProfiles))
	for _, p := range r.ConfigProfiles {
		out = append(out, p.profile())
	}
	return out, nil
}

// GetProfile returns one config profile.
func (c *Client) GetProfile(ctx context.Context, cred Credentials, uuid string) (Profile, error) {
	var r rawProfile
	if err := c.do(ctx, cred, http.MethodGet, "/api/config-profiles/"+url.PathEscape(uuid), nil, &r); err != nil {
		return Profile{}, err
	}
	return r.profile(), nil
}

// UpdateProfileConfig replaces the Xray configuration of a profile.
func (c *Client) UpdateProfileConfig(ctx context.Context, cred Credentials, uuid string, cfg map[string]any) error {
	body := map[string]any{"uuid": uuid, "config": cfg}
	return c.do(ctx, cred, http.MethodPatch, "/api/config-profiles", body, nil)
}

// NodeAddress returns the public address of a node.
func (c *Client) NodeAddress(ctx context.Context, cred Credentials, uuid string) (string, error) {
	var r struct {
		Address string `json:"address"`
	}
	if err := c.do(ctx, cred, http.MethodGet, "/api/nodes/"+url.PathEscape(uuid), nil, &r); err != nil {
		return "", err
	}
	return r.Address, nil
}

// GetUser returns a user by id.
func (c *Client) GetUser(ctx context.Context, cred Credentials, id int64) (User, error) {
	var u User
	err := c.do(ctx, cred, http.MethodGet, "/api/users/"+strconv.FormatInt(id, 10), nil, &u)
	return u, err
}

// GetUserByUsername returns a user by username.
func (c *Client) GetUserByUsername(ctx context.Context, cred Credentials, name string) (User, error) {
	var u User
	err := c.do(ctx, cred, http.MethodGet, "/api/users/by-username/"+url.PathEscape(name), nil, &u)
	return u, err
}

// CreateUser creates a user without squads and with a far expiry.
func (c *Client) CreateUser(ctx context.Context, cred Credentials, name string) (User, error) {
	var u User
	body := map[string]any{"username": name, "expireAt": farFuture}
	err := c.do(ctx, cred, http.MethodPost, "/api/users", body, &u)
	return u, err
}
