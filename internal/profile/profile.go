// Package profile reads and edits WireGuard peers inside a Remnawave config
// profile, keeping every other part of the configuration untouched.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// Errors returned by profile edits; callers map them to HTTP statuses.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

// Peer is a WireGuard peer as stored in the inbound settings.
type Peer struct {
	Email        string   `json:"email"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
}

// Inbound is a WireGuard inbound of a config profile.
type Inbound struct {
	Tag       string
	Port      int
	SecretKey string
	Address   []string
	Peers     []Peer
}

type rawInbound struct {
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Settings struct {
		SecretKey string   `json:"secretKey"`
		Address   []string `json:"address"`
		Peers     []Peer   `json:"peers"`
	} `json:"settings"`
}

// WireGuardInbounds returns every WireGuard inbound of the configuration.
func WireGuardInbounds(cfg map[string]any) []Inbound {
	list, _ := cfg["inbounds"].([]any)
	var out []Inbound
	for _, item := range list {
		var r rawInbound
		if err := remarshal(item, &r); err != nil || r.Protocol != "wireguard" {
			continue
		}
		out = append(out, Inbound{
			Tag: r.Tag, Port: r.Port, SecretKey: r.Settings.SecretKey,
			Address: r.Settings.Address, Peers: r.Settings.Peers,
		})
	}
	return out
}

// FindInbound returns the WireGuard inbound with the given tag.
func FindInbound(cfg map[string]any, tag string) (Inbound, error) {
	for _, in := range WireGuardInbounds(cfg) {
		if in.Tag == tag {
			return in, nil
		}
	}
	return Inbound{}, fmt.Errorf("wireguard inbound %q: %w", tag, ErrNotFound)
}

// Subnet returns the client subnet and the server address inside it.
func Subnet(in Inbound, prefixLen int) (netip.Prefix, netip.Addr, error) {
	for _, a := range in.Address {
		p, err := netip.ParsePrefix(a)
		if err == nil && p.Addr().Is4() {
			return p.Masked(), p.Addr(), nil
		}
	}
	for _, peer := range in.Peers {
		for _, a := range peer.AllowedIPs {
			p, err := netip.ParsePrefix(a)
			if err != nil || !p.Addr().Is4() {
				continue
			}
			subnet, err := p.Addr().Prefix(prefixLen)
			if err != nil {
				return netip.Prefix{}, netip.Addr{}, fmt.Errorf("prefix %d: %w", prefixLen, ErrInvalid)
			}
			return subnet, subnet.Addr().Next(), nil
		}
	}
	return netip.Prefix{}, netip.Addr{}, fmt.Errorf("cannot infer the client subnet of %q: set settings.address on the inbound or pass an address: %w", in.Tag, ErrInvalid)
}

func used(in Inbound) map[netip.Addr]bool {
	u := map[netip.Addr]bool{}
	for _, peer := range in.Peers {
		for _, a := range peer.AllowedIPs {
			if p, err := netip.ParsePrefix(a); err == nil {
				u[p.Addr()] = true
			}
		}
	}
	return u
}

func free(in Inbound, prefixLen int) ([]netip.Addr, error) {
	subnet, server, err := Subnet(in, prefixLen)
	if err != nil {
		return nil, err
	}
	u := used(in)
	var out []netip.Addr
	for a := subnet.Addr().Next(); subnet.Contains(a); a = a.Next() {
		if !subnet.Contains(a.Next()) { // broadcast
			break
		}
		if a != server && !u[a] {
			out = append(out, a)
		}
	}
	return out, nil
}

// NextFreeAddress returns the lowest unused client address of the inbound.
func NextFreeAddress(in Inbound, prefixLen int) (netip.Addr, error) {
	f, err := free(in, prefixLen)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(f) == 0 {
		return netip.Addr{}, fmt.Errorf("no free addresses in %q: %w", in.Tag, ErrConflict)
	}
	return f[0], nil
}

// FreeCount returns how many client addresses of the inbound are unused.
func FreeCount(in Inbound, prefixLen int) (int, error) {
	f, err := free(in, prefixLen)
	return len(f), err
}

// AddPeer returns a copy of cfg with the peer appended to the inbound.
func AddPeer(cfg map[string]any, tag string, p Peer) (map[string]any, error) {
	in, err := FindInbound(cfg, tag)
	if err != nil {
		return nil, err
	}
	u := used(in)
	for _, old := range in.Peers {
		if old.Email == p.Email || old.PublicKey == p.PublicKey {
			return nil, fmt.Errorf("peer %q: %w", p.Email, ErrConflict)
		}
	}
	for _, a := range p.AllowedIPs {
		if pr, err := netip.ParsePrefix(a); err != nil {
			return nil, fmt.Errorf("address %q: %w", a, ErrInvalid)
		} else if u[pr.Addr()] {
			return nil, fmt.Errorf("address %q: %w", a, ErrConflict)
		}
	}
	out, settings, err := copyAndLocate(cfg, tag)
	if err != nil {
		return nil, err
	}
	var entry map[string]any
	if err := remarshal(p, &entry); err != nil {
		return nil, err
	}
	peers, _ := settings["peers"].([]any)
	settings["peers"] = append(peers, entry)
	return out, nil
}

// RemovePeer returns a copy of cfg without the peer with the given email.
func RemovePeer(cfg map[string]any, tag, email string) (map[string]any, error) {
	out, settings, err := copyAndLocate(cfg, tag)
	if err != nil {
		return nil, err
	}
	peers, _ := settings["peers"].([]any)
	kept := make([]any, 0, len(peers))
	found := false
	for _, item := range peers {
		if m, ok := item.(map[string]any); ok && m["email"] == email {
			found = true
			continue
		}
		kept = append(kept, item)
	}
	if !found {
		return nil, fmt.Errorf("peer %q: %w", email, ErrNotFound)
	}
	settings["peers"] = kept
	return out, nil
}

// copyAndLocate deep-copies cfg and returns the settings map of the inbound.
func copyAndLocate(cfg map[string]any, tag string) (map[string]any, map[string]any, error) {
	var out map[string]any
	if err := remarshal(cfg, &out); err != nil {
		return nil, nil, err
	}
	list, _ := out["inbounds"].([]any)
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m == nil || m["tag"] != tag || m["protocol"] != "wireguard" {
			continue
		}
		settings, _ := m["settings"].(map[string]any)
		if settings == nil {
			return nil, nil, fmt.Errorf("inbound %q has no settings: %w", tag, ErrInvalid)
		}
		return out, settings, nil
	}
	return nil, nil, fmt.Errorf("wireguard inbound %q: %w", tag, ErrNotFound)
}

func remarshal(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
