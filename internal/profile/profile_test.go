package profile

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const sampleConfig = `{
  "log": {"loglevel": "warning"},
  "geodata": {"core": {"url": "https://example.com/xray", "sha256": "abc"}},
  "inbounds": [
    {"tag": "vless-in", "port": 443, "protocol": "vless", "settings": {"clients": [], "decryption": "none"}},
    {"tag": "wg-in", "port": 51820, "protocol": "wireguard",
     "settings": {"mtu": 1420, "secretKey": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "noKernelTun": true,
       "peers": [
         {"email": "76", "publicKey": "pubA", "preSharedKey": "pskA", "allowedIPs": ["10.66.0.2/32"]},
         {"email": "cudy", "publicKey": "pubB", "allowedIPs": ["10.66.0.3/32"]}
       ]}}
  ],
  "routing": {"rules": [{"inboundTag": ["wg-in"], "outboundTag": "direct"}]}
}`

func load(t *testing.T) map[string]any {
	t.Helper()
	// Decode like the panel client does, numbers as json.Number.
	dec := json.NewDecoder(strings.NewReader(sampleConfig))
	dec.UseNumber()
	var cfg map[string]any
	if err := dec.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWireGuardInbounds(t *testing.T) {
	ins := WireGuardInbounds(load(t))
	if len(ins) != 1 || ins[0].Tag != "wg-in" || ins[0].Port != 51820 || len(ins[0].Peers) != 2 {
		t.Fatalf("got %+v", ins)
	}
	if ins[0].Peers[1].PreSharedKey != "" || ins[0].Peers[0].AllowedIPs[0] != "10.66.0.2/32" {
		t.Fatalf("peers %+v", ins[0].Peers)
	}
}

func TestFindInboundNotFound(t *testing.T) {
	if _, err := FindInbound(load(t), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v, want ErrNotFound", err)
	}
	if _, err := FindInbound(load(t), "vless-in"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-wireguard inbound: err %v, want ErrNotFound", err)
	}
}

func TestSubnetFromPeers(t *testing.T) {
	in, _ := FindInbound(load(t), "wg-in")
	p, server, err := Subnet(in, 24)
	if err != nil {
		t.Fatal(err)
	}
	if p != netip.MustParsePrefix("10.66.0.0/24") || server != netip.MustParseAddr("10.66.0.1") {
		t.Fatalf("subnet %v server %v", p, server)
	}
}

func TestSubnetFromAddressField(t *testing.T) {
	in := Inbound{Address: []string{"10.9.0.1/16"}}
	p, server, err := Subnet(in, 24)
	if err != nil {
		t.Fatal(err)
	}
	if p != netip.MustParsePrefix("10.9.0.0/16") || server != netip.MustParseAddr("10.9.0.1") {
		t.Fatalf("subnet %v server %v", p, server)
	}
}

func TestSubnetUnknown(t *testing.T) {
	if _, _, err := Subnet(Inbound{}, 24); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err %v, want ErrInvalid", err)
	}
}

func TestNextFreeAddress(t *testing.T) {
	in, _ := FindInbound(load(t), "wg-in")
	a, err := NextFreeAddress(in, 24)
	if err != nil {
		t.Fatal(err)
	}
	if a != netip.MustParseAddr("10.66.0.4") {
		t.Fatalf("got %v, want 10.66.0.4", a)
	}
}

func TestNextFreeAddressExhausted(t *testing.T) {
	in := Inbound{Peers: []Peer{
		{Email: "a", AllowedIPs: []string{"10.66.0.2/32"}},
	}}
	// /30: network .0, server .1, client .2, broadcast .3 — nothing left.
	if _, err := NextFreeAddress(in, 30); !errors.Is(err, ErrConflict) {
		t.Fatalf("err %v, want ErrConflict", err)
	}
	if n, _ := FreeCount(in, 30); n != 0 {
		t.Fatalf("free %d, want 0", n)
	}
}

func TestAddPeer(t *testing.T) {
	cfg := load(t)
	out, err := AddPeer(cfg, "wg-in", Peer{Email: "77", PublicKey: "pubC", PreSharedKey: "pskC", AllowedIPs: []string{"10.66.0.4/32"}})
	if err != nil {
		t.Fatal(err)
	}
	in, _ := FindInbound(out, "wg-in")
	if len(in.Peers) != 3 || in.Peers[2].Email != "77" {
		t.Fatalf("peers %+v", in.Peers)
	}
	// The input must not be modified.
	orig, _ := FindInbound(cfg, "wg-in")
	if len(orig.Peers) != 2 {
		t.Fatal("AddPeer modified its input")
	}
}

func TestAddPeerPreservesUnrelatedFields(t *testing.T) {
	cfg := load(t)
	out, err := AddPeer(cfg, "wg-in", Peer{Email: "77", PublicKey: "pubC", PreSharedKey: "pskC", AllowedIPs: []string{"10.66.0.4/32"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := RemovePeer(out, "wg-in", "77")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, cfg) {
		t.Fatalf("add+remove changed the config:\n got %v\nwant %v", back, cfg)
	}
}

func TestAddPeerWritesOnlyKnownFields(t *testing.T) {
	out, _ := AddPeer(load(t), "wg-in", Peer{Email: "77", PublicKey: "pubC", PreSharedKey: "pskC", AllowedIPs: []string{"10.66.0.4/32"}})
	peers := out["inbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["peers"].([]any)
	last := peers[2].(map[string]any)
	if len(last) != 4 {
		t.Fatalf("peer has fields %v, want exactly email, publicKey, preSharedKey, allowedIPs", last)
	}
}

func TestAddPeerConflicts(t *testing.T) {
	cases := map[string]Peer{
		"email":   {Email: "76", PublicKey: "x", AllowedIPs: []string{"10.66.0.9/32"}},
		"key":     {Email: "99", PublicKey: "pubA", AllowedIPs: []string{"10.66.0.9/32"}},
		"address": {Email: "99", PublicKey: "x", AllowedIPs: []string{"10.66.0.2/32"}},
	}
	for name, p := range cases {
		if _, err := AddPeer(load(t), "wg-in", p); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: err %v, want ErrConflict", name, err)
		}
	}
}

func TestRemovePeerNotFound(t *testing.T) {
	if _, err := RemovePeer(load(t), "wg-in", "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v, want ErrNotFound", err)
	}
}

func TestValidateAddress(t *testing.T) {
	in := Inbound{Tag: "wg", Address: []string{"10.0.0.1/24"}, Peers: []Peer{{Email: "a", AllowedIPs: []string{"10.0.0.2/32"}}}}
	bad := map[string]error{
		"10.0.0.1":   ErrInvalid,  // server
		"10.0.0.0":   ErrInvalid,  // network
		"10.0.0.255": ErrInvalid,  // broadcast
		"10.1.0.5":   ErrInvalid,  // outside the subnet
		"fd00::5":    ErrInvalid,  // IPv6
		"10.0.0.2":   ErrConflict, // taken
	}
	for s, want := range bad {
		if err := ValidateAddress(in, 24, netip.MustParseAddr(s)); !errors.Is(err, want) {
			t.Errorf("%s: err %v, want %v", s, err, want)
		}
	}
	if err := ValidateAddress(in, 24, netip.MustParseAddr("10.0.0.3")); err != nil {
		t.Fatalf("10.0.0.3: %v", err)
	}
}

func TestWireGuardInboundsToleratesOddFields(t *testing.T) {
	var cfg map[string]any
	raw := `{"inbounds":[{"tag":"wg","port":"51820","protocol":"wireguard","settings":{"secretKey":"k","peers":[
	  {"email":5,"publicKey":"a","allowedIPs":["10.66.0.2/32"]},
	  {"email":"ok","publicKey":"b","allowedIPs":"10.66.0.3/32"},
	  {"email":"good","publicKey":"c","allowedIPs":["10.66.0.4/32"]}]}}]}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	ins := WireGuardInbounds(cfg)
	if len(ins) != 1 || ins[0].Port != 51820 || len(ins[0].Peers) != 3 {
		t.Fatalf("got %+v", ins)
	}
	if ins[0].Peers[0].Email != "5" || ins[0].Peers[2].AllowedIPs[0] != "10.66.0.4/32" {
		t.Fatalf("peers %+v", ins[0].Peers)
	}
}

func TestWideSubnetIsCountedWithoutEnumeration(t *testing.T) {
	in := Inbound{Address: []string{"10.0.0.1/8"}, Peers: []Peer{{Email: "a", AllowedIPs: []string{"10.0.0.2/32"}}}}
	n, err := FreeCount(in, 24)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1<<24 - 2 - 1 - 1; n != want {
		t.Fatalf("free %d, want %d", n, want)
	}
	a, err := NextFreeAddress(in, 24)
	if err != nil || a != netip.MustParseAddr("10.0.0.3") {
		t.Fatalf("next %v, err %v", a, err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = FreeCount(in, 24)
	_, _ = NextFreeAddress(in, 24)
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
		t.Fatalf("allocated %d bytes; the subnet must not be enumerated", d)
	}
}

func TestAddPeerPreservesBigIntegers(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"stats":{"big":9007199254740993},` + sampleConfig[1:]))
	dec.UseNumber()
	var cfg map[string]any
	if err := dec.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	out, err := AddPeer(cfg, "wg-in", Peer{Email: "77", PublicKey: "pubC", AllowedIPs: []string{"10.66.0.4/32"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "9007199254740993") {
		t.Fatalf("big integer changed: %s", b)
	}
}
