package clients

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
	"github.com/kroticw/remnawave-wg-manager/internal/wgkey"
)

const serverKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

type fakePanel struct {
	cfg       map[string]any
	users     map[int64]string
	nextID    int64
	updates   int
	beforeGet func(f *fakePanel)
}

func newFake(t *testing.T, peers string) *fakePanel {
	t.Helper()
	raw := `{"inbounds":[{"tag":"wg","port":443,"protocol":"wireguard","settings":{"secretKey":"` + serverKey + `","peers":` + peers + `}}],"routing":{"rules":[]}}`
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	return &fakePanel{cfg: cfg, users: map[int64]string{76: "alice"}, nextID: 100}
}

// clone returns a deep copy, as a real panel returns a fresh document on every read.
func clone(cfg map[string]any) map[string]any {
	b, _ := json.Marshal(cfg)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (f *fakePanel) ListProfiles(context.Context, panel.Credentials) ([]panel.Profile, error) {
	return []panel.Profile{{UUID: "u1", Name: "p", Config: clone(f.cfg), NodeUUIDs: []string{"n1"}}}, nil
}
func (f *fakePanel) GetProfile(context.Context, panel.Credentials, string) (panel.Profile, error) {
	if f.beforeGet != nil {
		f.beforeGet(f)
	}
	return panel.Profile{UUID: "u1", Name: "p", Config: clone(f.cfg), NodeUUIDs: []string{"n1"}}, nil
}
func (f *fakePanel) UpdateProfileConfig(_ context.Context, _ panel.Credentials, _ string, cfg map[string]any) error {
	f.cfg = cfg
	f.updates++
	return nil
}
func (f *fakePanel) NodeAddress(context.Context, panel.Credentials, string) (string, error) {
	return "203.0.113.1", nil
}
func (f *fakePanel) GetUser(_ context.Context, _ panel.Credentials, id int64) (panel.User, error) {
	if n, ok := f.users[id]; ok {
		return panel.User{ID: id, Username: n}, nil
	}
	return panel.User{}, &panel.Error{Status: 404}
}
func (f *fakePanel) GetUserByUsername(_ context.Context, _ panel.Credentials, name string) (panel.User, error) {
	for id, n := range f.users {
		if n == name {
			return panel.User{ID: id, Username: n}, nil
		}
	}
	return panel.User{}, &panel.Error{Status: 404}
}
func (f *fakePanel) ListUsers(context.Context, panel.Credentials) ([]panel.User, error) {
	var out []panel.User
	for id, n := range f.users {
		out = append(out, panel.User{ID: id, Username: n})
	}
	return out, nil
}
func (f *fakePanel) CreateUser(_ context.Context, _ panel.Credentials, name string) (panel.User, error) {
	f.nextID++
	f.users[f.nextID] = name
	return panel.User{ID: f.nextID, Username: name}, nil
}

func manager(f *fakePanel) *Manager {
	return &Manager{Panel: f, SubnetPrefix: 24, DNS: "1.1.1.1", MTU: 1380}
}

var cred = panel.Credentials{Token: "t", Browser: true}

func TestCreateExistingUserAndConfig(t *testing.T) {
	f := newFake(t, `[{"email":"cudy","publicKey":"manualPub","allowedIPs":["10.66.0.2/32"]}]`)
	m := manager(f)
	c, err := m.Create(context.Background(), cred, "p", "wg", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "76" || c.Username != "alice" || c.Address != "10.66.0.3" || !c.Managed {
		t.Fatalf("client %+v", c)
	}
	conf, err := m.Config(context.Background(), cred, "p", "wg", "76")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.66.0.3/32", "Endpoint = 203.0.113.1:443", "DNS = 1.1.1.1", "MTU = 1380"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("config misses %q:\n%s", want, conf)
		}
	}
	// The private key in the config must match the stored public key.
	in, _ := profile.FindInbound(f.cfg, "wg")
	priv, _ := wgkey.ParseKey(strings.TrimSpace(strings.SplitN(strings.SplitN(conf, "PrivateKey = ", 2)[1], "\n", 2)[0]))
	pub, _ := wgkey.PublicKey(priv)
	if pub.String() != in.Peers[1].PublicKey {
		t.Fatal("config private key does not match the peer public key")
	}
}

func TestCreateNewUser(t *testing.T) {
	f := newFake(t, `[{"email":"cudy","publicKey":"manualPub","allowedIPs":["10.66.0.2/32"]}]`)
	c, err := manager(f).Create(context.Background(), cred, "p", "wg", "bob-phone", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "101" || c.Username != "bob-phone" {
		t.Fatalf("client %+v", c)
	}
}

func TestCreateRejectsBadName(t *testing.T) {
	f := newFake(t, `[]`)
	for _, name := range []string{"Bob", "a", "имя", "x y", "-lead", strings.Repeat("a", 33)} {
		if _, err := manager(f).Create(context.Background(), cred, "p", "wg", name, ""); !errors.Is(err, profile.ErrInvalid) {
			t.Errorf("%q: err %v, want ErrInvalid", name, err)
		}
	}
	if f.updates != 0 {
		t.Fatal("invalid names must not touch the profile")
	}
}

func TestCreateUsesFreshProfile(t *testing.T) {
	f := newFake(t, `[{"email":"cudy","publicKey":"manualPub","allowedIPs":["10.66.0.2/32"]}]`)
	calls := 0
	f.beforeGet = func(f *fakePanel) {
		calls++
		if calls == 2 { // someone edits the profile in the panel before our write
			f.cfg["routing"] = map[string]any{"rules": []any{"edited-in-panel"}}
		}
	}
	if _, err := manager(f).Create(context.Background(), cred, "p", "wg", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if rules := f.cfg["routing"].(map[string]any)["rules"].([]any); len(rules) != 1 || rules[0] != "edited-in-panel" {
		t.Fatalf("the write was based on a stale profile: %v", f.cfg["routing"])
	}
}

func TestClientsWithManualPeers(t *testing.T) {
	f := newFake(t, `[
	  {"email":"cudy","publicKey":"manualPub","allowedIPs":["10.66.0.2/32"]},
	  {"email":"76","publicKey":"broken","preSharedKey":"also-broken","allowedIPs":["10.66.0.3/32"]}
	]`)
	m := manager(f)
	list, err := m.Clients(context.Background(), cred, "p", "wg")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Managed || list[1].Managed || list[1].Username != "alice" || list[0].Username != "" {
		t.Fatalf("list %+v", list)
	}
	if _, err := m.Config(context.Background(), cred, "p", "wg", "cudy"); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("err %v, want ErrNotManaged", err)
	}
}

func TestDelete(t *testing.T) {
	f := newFake(t, `[{"email":"76","publicKey":"k","allowedIPs":["10.66.0.2/32"]}]`)
	m := manager(f)
	if err := m.Delete(context.Background(), cred, "p", "wg", "76"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(context.Background(), cred, "p", "wg", "76"); !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("second delete: err %v, want ErrNotFound", err)
	}
}

func TestInbounds(t *testing.T) {
	f := newFake(t, `[{"email":"76","publicKey":"k","allowedIPs":["10.66.0.2/32"]}]`)
	list, err := manager(f).Inbounds(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	want := InboundInfo{Profile: "p", Tag: "wg", Port: 443, Subnet: "10.66.0.0/24", Endpoint: "203.0.113.1:443", Free: 252}
	if len(list) != 1 || list[0] != want {
		t.Fatalf("got %+v, want %+v", list, want)
	}
}

func TestCreateOnEmptyInbound(t *testing.T) {
	f := newFake(t, `[]`)
	m := manager(f)
	if _, err := m.Create(context.Background(), cred, "p", "wg", "alice", ""); !errors.Is(err, profile.ErrInvalid) {
		t.Fatalf("no subnet known: err %v, want ErrInvalid", err)
	}
	if f.updates != 0 {
		t.Fatal("a failed create must not touch the profile")
	}
	c, err := m.Create(context.Background(), cred, "p", "wg", "alice", "10.8.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != "10.8.0.2" {
		t.Fatalf("client %+v", c)
	}
}

func TestCreateRejectsBadAddress(t *testing.T) {
	f := newFake(t, `[{"email":"cudy","publicKey":"manualPub","allowedIPs":["10.66.0.2/32"]}]`)
	m := manager(f)
	for addr, want := range map[string]error{
		"10.66.0.1":   profile.ErrInvalid, // server
		"10.66.0.255": profile.ErrInvalid, // broadcast
		"10.67.0.5":   profile.ErrInvalid, // outside the subnet
		"fd00::5":     profile.ErrInvalid, // IPv6
		"10.66.0.2":   profile.ErrConflict,
	} {
		if _, err := m.Create(context.Background(), cred, "p", "wg", "alice", addr); !errors.Is(err, want) {
			t.Errorf("%s: err %v, want %v", addr, err, want)
		}
	}
	if f.updates != 0 {
		t.Fatal("rejected addresses must not touch the profile")
	}
}

func TestUsers(t *testing.T) {
	f := newFake(t, `[]`)
	users, err := manager(f).Users(context.Background(), cred)
	if err != nil || len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("users %+v, err %v", users, err)
	}
}
