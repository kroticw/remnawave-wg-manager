// Package profile reads and edits WireGuard peers inside a Remnawave config
// profile, keeping every other part of the configuration untouched.
package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
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

// WireGuardInbounds returns every WireGuard inbound of the configuration.
// Fields are read leniently: a malformed peer or a port given as a string
// must not hide the whole inbound.
func WireGuardInbounds(cfg map[string]any) []Inbound {
	list, _ := cfg["inbounds"].([]any)
	var out []Inbound
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m == nil || m["protocol"] != "wireguard" {
			continue
		}
		settings, _ := m["settings"].(map[string]any)
		in := Inbound{
			Tag:       text(m["tag"]),
			Port:      port(m["port"]),
			SecretKey: text(settings["secretKey"]),
			Address:   texts(settings["address"]),
		}
		peers, _ := settings["peers"].([]any)
		for _, item := range peers {
			pm, _ := item.(map[string]any)
			if pm == nil {
				continue
			}
			in.Peers = append(in.Peers, Peer{
				Email:        text(pm["email"]),
				PublicKey:    text(pm["publicKey"]),
				PreSharedKey: text(pm["preSharedKey"]),
				AllowedIPs:   texts(pm["allowedIPs"]),
			})
		}
		out = append(out, in)
	}
	return out
}

// text renders a scalar JSON value as a string; missing values become "".
func text(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// texts accepts both a list of strings and a single string.
func texts(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, text(x))
		}
		return out
	default:
		return nil
	}
}

// port reads a port given as a number or a numeric string; ranges give 0.
func port(v any) int {
	n, err := strconv.Atoi(text(v))
	if err != nil {
		return 0
	}
	return n
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

// broadcast returns the last address of an IPv4 prefix.
func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (1<<(32-p.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// isHost reports whether a is a usable host address of the subnet.
func isHost(subnet netip.Prefix, a netip.Addr) bool {
	return a.Is4() && subnet.Contains(a) && a != subnet.Masked().Addr() && a != broadcast(subnet)
}

// NextFreeAddress returns the lowest unused client address of the inbound.
// It stops at the first free address, so wide subnets cost nothing extra.
func NextFreeAddress(in Inbound, prefixLen int) (netip.Addr, error) {
	subnet, server, err := Subnet(in, prefixLen)
	if err != nil {
		return netip.Addr{}, err
	}
	u := used(in)
	for a := subnet.Masked().Addr().Next(); isHost(subnet, a); a = a.Next() {
		if a != server && !u[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free addresses in %q: %w", in.Tag, ErrConflict)
}

// FreeCount returns how many client addresses of the inbound are unused.
func FreeCount(in Inbound, prefixLen int) (int, error) {
	subnet, server, err := Subnet(in, prefixLen)
	if err != nil {
		return 0, err
	}
	n := 1<<(32-subnet.Bits()) - 2
	if isHost(subnet, server) {
		n--
	}
	for a := range used(in) {
		if a != server && isHost(subnet, a) {
			n--
		}
	}
	return max(n, 0), nil
}

// ValidateAddress checks an address chosen by hand for a new client: an
// IPv4 host address of the inbound subnet that is neither the server's nor
// taken by another peer. When the subnet is unknown only the last check runs.
func ValidateAddress(in Inbound, prefixLen int, a netip.Addr) error {
	if !a.Is4() {
		return fmt.Errorf("address %s: only IPv4 is supported: %w", a, ErrInvalid)
	}
	if subnet, server, err := Subnet(in, prefixLen); err == nil {
		if !isHost(subnet, a) || a == server {
			return fmt.Errorf("address %s is not a free host address of %s: %w", a, subnet, ErrInvalid)
		}
	}
	if used(in)[a] {
		return fmt.Errorf("address %s: %w", a, ErrConflict)
	}
	return nil
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
		if m, ok := item.(map[string]any); ok && text(m["email"]) == email {
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
	// UseNumber keeps integers beyond 2^53 intact through the copy.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
