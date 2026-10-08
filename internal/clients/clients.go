// Package clients implements the WireGuard client operations on top of the
// panel API, profile editing and key derivation.
package clients

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"sync"

	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
	"github.com/kroticw/remnawave-wg-manager/internal/wgconf"
	"github.com/kroticw/remnawave-wg-manager/internal/wgkey"
)

// ErrNotManaged means the peer's key cannot be derived, so its config cannot be rebuilt.
var ErrNotManaged = errors.New("client key is not managed by this service")

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// Panel is the part of the panel API the manager uses.
type Panel interface {
	ListProfiles(ctx context.Context, cred panel.Credentials) ([]panel.Profile, error)
	GetProfile(ctx context.Context, cred panel.Credentials, uuid string) (panel.Profile, error)
	UpdateProfileConfig(ctx context.Context, cred panel.Credentials, uuid string, cfg map[string]any) error
	GetNode(ctx context.Context, cred panel.Credentials, uuid string) (panel.Node, error)
	GetUser(ctx context.Context, cred panel.Credentials, id int64) (panel.User, error)
	GetUserByUsername(ctx context.Context, cred panel.Credentials, name string) (panel.User, error)
	CreateUser(ctx context.Context, cred panel.Credentials, name string) (panel.User, error)
	ListUsers(ctx context.Context, cred panel.Credentials) ([]panel.User, error)
}

// Manager runs client operations. It serializes profile edits.
type Manager struct {
	Panel        Panel
	SubnetPrefix int
	EndpointHost string
	DNS          string
	MTU          int

	mu sync.Mutex
}

// InboundInfo describes a WireGuard inbound for listing.
type InboundInfo struct {
	Profile  string `json:"profile"`
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Subnet   string `json:"subnet"`
	Endpoint string `json:"endpoint"`
	Free     int    `json:"free"`
}

// ClientInfo describes a WireGuard client (peer).
type ClientInfo struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Address  string `json:"address"`
	Managed  bool   `json:"managed"`
}

func (m *Manager) findProfile(ctx context.Context, cred panel.Credentials, name string) (panel.Profile, error) {
	list, err := m.Panel.ListProfiles(ctx, cred)
	if err != nil {
		return panel.Profile{}, err
	}
	for _, p := range list {
		if p.Name == name {
			return m.Panel.GetProfile(ctx, cred, p.UUID)
		}
	}
	return panel.Profile{}, fmt.Errorf("profile %q: %w", name, profile.ErrNotFound)
}

func (m *Manager) endpoint(ctx context.Context, cred panel.Credentials, p panel.Profile, port int) (string, error) {
	host := m.EndpointHost
	if host == "" {
		addr, err := m.nodeHost(ctx, cred, p)
		if err != nil {
			return "", err
		}
		host = addr
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// nodeHost picks the address of the first connected and enabled node of the
// profile. The panel sends a WireGuard inbound to every node of its profile,
// so any live node serves it; a dead first node must not end up in configs.
// With no live node the first one is used, as there is nothing better.
func (m *Manager) nodeHost(ctx context.Context, cred panel.Credentials, p panel.Profile) (string, error) {
	if len(p.NodeUUIDs) == 0 {
		return "", fmt.Errorf("profile %q has no nodes: %w", p.Name, profile.ErrInvalid)
	}
	var first string
	for i, id := range p.NodeUUIDs {
		n, err := m.Panel.GetNode(ctx, cred, id)
		if err != nil {
			return "", err
		}
		if i == 0 {
			first = n.Address
		}
		if n.IsConnected && !n.IsDisabled {
			return n.Address, nil
		}
	}
	return first, nil
}

// Users lists panel users for picking the owner of a new client.
func (m *Manager) Users(ctx context.Context, cred panel.Credentials) ([]panel.User, error) {
	return m.Panel.ListUsers(ctx, cred)
}

// Inbounds lists WireGuard inbounds of all profiles.
func (m *Manager) Inbounds(ctx context.Context, cred panel.Credentials) ([]InboundInfo, error) {
	list, err := m.Panel.ListProfiles(ctx, cred)
	if err != nil {
		return nil, err
	}
	var out []InboundInfo
	for _, p := range list {
		for _, in := range profile.WireGuardInbounds(p.Config) {
			info := InboundInfo{Profile: p.Name, Tag: in.Tag, Port: in.Port}
			if subnet, _, err := profile.Subnet(in, m.SubnetPrefix); err == nil {
				info.Subnet = subnet.String()
				info.Free, _ = profile.FreeCount(in, m.SubnetPrefix)
			}
			if ep, err := m.endpoint(ctx, cred, p, in.Port); err == nil {
				info.Endpoint = ep
			}
			out = append(out, info)
		}
	}
	return out, nil
}

func managed(server wgkey.Key, peer profile.Peer) bool {
	psk, err := wgkey.ParseKey(peer.PreSharedKey)
	if err != nil {
		return false
	}
	priv, err := wgkey.DeriveClient(server, psk, peer.Email)
	if err != nil {
		return false
	}
	pub, err := wgkey.PublicKey(priv)
	return err == nil && pub.String() == peer.PublicKey
}

func address(peer profile.Peer) string {
	for _, a := range peer.AllowedIPs {
		if p, err := netip.ParsePrefix(a); err == nil {
			return p.Addr().String()
		}
	}
	return ""
}

// Clients lists the peers of an inbound.
func (m *Manager) Clients(ctx context.Context, cred panel.Credentials, profileName, tag string) ([]ClientInfo, error) {
	p, err := m.findProfile(ctx, cred, profileName)
	if err != nil {
		return nil, err
	}
	in, err := profile.FindInbound(p.Config, tag)
	if err != nil {
		return nil, err
	}
	server, serverErr := wgkey.ParseKey(in.SecretKey)
	out := make([]ClientInfo, 0, len(in.Peers))
	for _, peer := range in.Peers {
		c := ClientInfo{Email: peer.Email, Address: address(peer), Managed: serverErr == nil && managed(server, peer)}
		if id, err := strconv.ParseInt(peer.Email, 10, 64); err == nil {
			if u, err := m.Panel.GetUser(ctx, cred, id); err == nil {
				c.Username = u.Username
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *Manager) resolveUser(ctx context.Context, cred panel.Credentials, user string) (panel.User, error) {
	if id, err := strconv.ParseInt(user, 10, 64); err == nil {
		return m.Panel.GetUser(ctx, cred, id)
	}
	if !nameRe.MatchString(user) {
		return panel.User{}, fmt.Errorf("user name %q: %w", user, profile.ErrInvalid)
	}
	u, err := m.Panel.GetUserByUsername(ctx, cred, user)
	var pe *panel.Error
	if errors.As(err, &pe) && pe.Status == 404 {
		return m.Panel.CreateUser(ctx, cred, user)
	}
	return u, err
}

// Create adds a peer bound to a panel user, creating the user when needed.
func (m *Manager) Create(ctx context.Context, cred panel.Credentials, profileName, tag, user, addr string) (ClientInfo, error) {
	if _, err := strconv.ParseInt(user, 10, 64); err != nil && !nameRe.MatchString(user) {
		return ClientInfo{}, fmt.Errorf("user name %q: %w", user, profile.ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.findProfile(ctx, cred, profileName); err != nil {
		return ClientInfo{}, err
	}
	u, err := m.resolveUser(ctx, cred, user)
	if err != nil {
		return ClientInfo{}, err
	}
	email := strconv.FormatInt(u.ID, 10)

	// Re-read right before the write so the edit applies to the latest profile.
	p, err := m.findProfile(ctx, cred, profileName)
	if err != nil {
		return ClientInfo{}, err
	}
	in, err := profile.FindInbound(p.Config, tag)
	if err != nil {
		return ClientInfo{}, err
	}
	server, err := wgkey.ParseKey(in.SecretKey)
	if err != nil {
		return ClientInfo{}, fmt.Errorf("server key of %q: %w", tag, profile.ErrInvalid)
	}
	var a netip.Addr
	if addr == "" {
		if a, err = profile.NextFreeAddress(in, m.SubnetPrefix); err != nil {
			return ClientInfo{}, err
		}
	} else if a, err = netip.ParseAddr(addr); err != nil {
		return ClientInfo{}, fmt.Errorf("address %q: %w", addr, profile.ErrInvalid)
	} else if err = profile.ValidateAddress(in, m.SubnetPrefix, a); err != nil {
		return ClientInfo{}, err
	}
	psk, err := wgkey.NewPSK()
	if err != nil {
		return ClientInfo{}, err
	}
	priv, err := wgkey.DeriveClient(server, psk, email)
	if err != nil {
		return ClientInfo{}, err
	}
	pub, err := wgkey.PublicKey(priv)
	if err != nil {
		return ClientInfo{}, err
	}
	peer := profile.Peer{Email: email, PublicKey: pub.String(), PreSharedKey: psk.String(), AllowedIPs: []string{a.String() + "/32"}}
	cfg, err := profile.AddPeer(p.Config, tag, peer)
	if err != nil {
		return ClientInfo{}, err
	}
	if err := m.Panel.UpdateProfileConfig(ctx, cred, p.UUID, cfg); err != nil {
		return ClientInfo{}, err
	}
	if err := m.verify(ctx, cred, profileName, tag, email, true); err != nil {
		return ClientInfo{}, err
	}
	return ClientInfo{Email: email, Username: u.Username, Address: a.String(), Managed: true}, nil
}

// Delete removes the peer with the given email.
func (m *Manager) Delete(ctx context.Context, cred panel.Credentials, profileName, tag, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.findProfile(ctx, cred, profileName)
	if err != nil {
		return err
	}
	cfg, err := profile.RemovePeer(p.Config, tag, email)
	if err != nil {
		return err
	}
	if err := m.Panel.UpdateProfileConfig(ctx, cred, p.UUID, cfg); err != nil {
		return err
	}
	return m.verify(ctx, cred, profileName, tag, email, false)
}

func (m *Manager) verify(ctx context.Context, cred panel.Credentials, profileName, tag, email string, present bool) error {
	p, err := m.findProfile(ctx, cred, profileName)
	if err != nil {
		return err
	}
	in, err := profile.FindInbound(p.Config, tag)
	if err != nil {
		return err
	}
	found := false
	for _, peer := range in.Peers {
		found = found || peer.Email == email
	}
	if found != present {
		return fmt.Errorf("profile did not change as expected for %q", email)
	}
	return nil
}

// Config rebuilds the client configuration of a managed peer.
func (m *Manager) Config(ctx context.Context, cred panel.Credentials, profileName, tag, email string) (string, error) {
	p, err := m.findProfile(ctx, cred, profileName)
	if err != nil {
		return "", err
	}
	in, err := profile.FindInbound(p.Config, tag)
	if err != nil {
		return "", err
	}
	server, err := wgkey.ParseKey(in.SecretKey)
	if err != nil {
		return "", fmt.Errorf("server key of %q: %w", tag, profile.ErrInvalid)
	}
	for _, peer := range in.Peers {
		if peer.Email != email {
			continue
		}
		if !managed(server, peer) {
			return "", fmt.Errorf("%q: %w", email, ErrNotManaged)
		}
		psk, _ := wgkey.ParseKey(peer.PreSharedKey)
		priv, _ := wgkey.DeriveClient(server, psk, peer.Email)
		serverPub, err := wgkey.PublicKey(server)
		if err != nil {
			return "", err
		}
		ep, err := m.endpoint(ctx, cred, p, in.Port)
		if err != nil {
			return "", err
		}
		return wgconf.Render(wgconf.Client{
			PrivateKey: priv.String(), Address: address(peer), DNS: m.DNS, MTU: m.MTU,
			ServerPublicKey: serverPub.String(), PresharedKey: peer.PreSharedKey, Endpoint: ep,
		}), nil
	}
	return "", fmt.Errorf("client %q: %w", email, profile.ErrNotFound)
}
