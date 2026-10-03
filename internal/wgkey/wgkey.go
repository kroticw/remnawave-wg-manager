// Package wgkey handles WireGuard keys and derives client keys that can be
// recomputed from data already stored in the server configuration.
package wgkey

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Size is the length of WireGuard keys and pre-shared keys.
const Size = 32

const derivationInfo = "remnawave-wg-manager/v1/client-key\x00"

// Key is a WireGuard private, public or pre-shared key.
type Key [Size]byte

// ParseKey decodes a standard base64 key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("decode key: %w", err)
	}
	if len(b) != Size {
		return k, fmt.Errorf("key must be %d bytes, got %d", Size, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// String encodes the key in standard base64, as WireGuard does.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// PublicKey returns the X25519 public key for a private key.
func PublicKey(private Key) (Key, error) {
	var pub Key
	p, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return pub, fmt.Errorf("x25519 private key: %w", err)
	}
	copy(pub[:], p.PublicKey().Bytes())
	return pub, nil
}

// NewPSK returns a random pre-shared key.
func NewPSK() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("random psk: %w", err)
	}
	return k, nil
}

// DeriveClient derives the client private key from the server private key,
// the peer's pre-shared key and the peer's email.
func DeriveClient(server, psk Key, email string) (Key, error) {
	var k Key
	b, err := hkdf.Key(sha256.New, server[:], psk[:], derivationInfo+email, Size)
	if err != nil {
		return k, fmt.Errorf("hkdf: %w", err)
	}
	copy(k[:], b)
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}
