package wgconf

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	got := Render(Client{
		PrivateKey: "priv", Address: "10.66.0.5", DNS: "1.1.1.1, 8.8.8.8", MTU: 1380,
		ServerPublicKey: "srv", PresharedKey: "psk", Endpoint: "203.0.113.1:443",
	})
	want := `[Interface]
PrivateKey = priv
Address = 10.66.0.5/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1380

[Peer]
PublicKey = srv
PresharedKey = psk
Endpoint = 203.0.113.1:443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderOmitsEmptyDNS(t *testing.T) {
	if strings.Contains(Render(Client{Address: "10.0.0.2", MTU: 1380}), "DNS") {
		t.Fatal("empty DNS must be omitted")
	}
}

func TestQRSVG(t *testing.T) {
	svg, err := QRSVG("[Interface]\nPrivateKey = x\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, "<svg ") || !strings.Contains(svg, "<path ") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("not an svg: %.80s", svg)
	}
}
