// Package wgconf renders WireGuard client configurations.
package wgconf

import (
	"fmt"
	"strings"
)

// Client holds everything needed to render a client configuration.
type Client struct {
	PrivateKey      string
	Address         string
	DNS             string
	MTU             int
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string
}

// Render returns the client configuration in wg-quick format.
func Render(c Client) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", c.Address)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	fmt.Fprintf(&b, "MTU = %d\n\n", c.MTU)
	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPublicKey)
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
