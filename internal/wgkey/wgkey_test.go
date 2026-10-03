package wgkey

import (
	"encoding/hex"
	"testing"
)

func mustHexKey(t *testing.T, s string) Key {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex key %q", s)
	}
	var k Key
	copy(k[:], b)
	return k
}

// RFC 7748, section 6.1: Alice's key pair.
func TestPublicKeyRFC7748(t *testing.T) {
	priv := mustHexKey(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want := mustHexKey(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	got, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("public key %x, want %x", got, want)
	}
}

func TestParseKeyRoundTrip(t *testing.T) {
	const s = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	k, err := ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if k.String() != s {
		t.Fatalf("round trip %q, want %q", k.String(), s)
	}
}

func TestParseKeyRejectsWrongLength(t *testing.T) {
	if _, err := ParseKey("AQID"); err == nil {
		t.Fatal("want error for a 3-byte key")
	}
	if _, err := ParseKey("not base64!"); err == nil {
		t.Fatal("want error for invalid base64")
	}
}

// Fixed vector, computed independently with Python hmac/hashlib.
func TestDeriveClientVector(t *testing.T) {
	server, _ := ParseKey("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	psk, _ := ParseKey("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
	got, err := DeriveClient(server, psk, "76")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "wK6AYPfzNWt9Rd9p1Q3gthIhP2AVO15Nb3kEHkECB2s=" {
		t.Fatalf("derived %s", got)
	}
	other, _ := DeriveClient(server, psk, "77")
	if other.String() != "SFKeWLE2c48EJ7xKmXElBKDFzSlZf8tOufWEgDaa5mE=" {
		t.Fatalf("derived for 77: %s", other)
	}
}

func TestDeriveClientDependsOnPSK(t *testing.T) {
	server, _ := ParseKey("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	a, _ := NewPSK()
	b, _ := NewPSK()
	ka, _ := DeriveClient(server, a, "76")
	kb, _ := DeriveClient(server, b, "76")
	if ka == kb {
		t.Fatal("different PSKs must give different client keys")
	}
}

func TestDeriveClientIsClamped(t *testing.T) {
	server, _ := ParseKey("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	psk, _ := NewPSK()
	k, _ := DeriveClient(server, psk, "1")
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatalf("key is not clamped: %x", k)
	}
}
