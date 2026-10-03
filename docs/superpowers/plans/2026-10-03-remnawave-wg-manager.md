# remnawave-wg-manager — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** сервис на Go, который через API панели Remnawave управляет пирами
WireGuard-инбаундов Xray: веб-страница под `/wg` в стиле панели, REST и MCP.

**Architecture:** один бинарь без состояния. Источник правды — конфиг-профили
панели; сервис читает их, правит `settings.peers` WireGuard-инбаунда и пишет
обратно тем же токеном, с которым пришёл запрос. Ключи клиентов выводятся
HKDF из ключа сервера и PSK пира, поэтому конфиг собирается заново по
запросу. Пир привязан к пользователю панели: `email` пира равен `id`
пользователя, и трафик считает панель.

**Tech Stack:** Go 1.27, `net/http`, `crypto/ecdh`, `crypto/hkdf`,
`github.com/modelcontextprotocol/go-sdk` v1.8.0, `rsc.io/qr` v0.2.0,
`golangci-lint`, distroless.

**Spec:** [`docs/design.md`](../../design.md)

## Global Constraints

- Модуль `github.com/kroticw/remnawave-wg-manager`, `go 1.27`.
- Никаких секретов в конфигурации сервиса и никакого состояния на диске.
- Имя нового пользователя панели: `^[a-z0-9][a-z0-9_-]{2,31}$`.
- В запись пира добавляются только `email`, `publicKey`, `preSharedKey`,
  `allowedIPs` — Xray на ноде может разбирать JSON строго.
- Все остальные поля конфига профиля переживают правку без изменений.
- Вывод ключа: `HKDF-SHA256(ikm=secretKey сервера, salt=PSK пира,
  info="remnawave-wg-manager/v1/client-key\x00"+email, 32)`, затем clamp.
- JWT из браузера идёт в панель с заголовком `x-remnawave-client-type: browser`;
  API-токен из MCP — без него.
- CSP страницы: `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data: blob:; font-src 'self'; connect-src 'self';
  frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
- Пользовательские строки на странице — только через `textContent`.
- Без внешних CDN во время работы; шрифты и иконки вшиты в бинарь.
- Каждое изменение пиров перезапускает Xray на нодах профиля — интерфейсы об
  этом предупреждают.
- `golangci-lint run` — ноль замечаний; `go test -race ./...` — зелёный.
- Коммиты: `git commit --signoff`, подпись GPG, формат `type(scope): ...`.

## Review Focus

1. **Поля профиля, о которых сервис не знает,** — правка пиров не должна
   терять или менять ни одного из них (нода, роутинг, `geodata`,
   балансировщики). Тест: Task 2, `TestAddPeerPreservesUnrelatedFields`.
2. **Профиль поменяли в панели между нашим чтением и записью** — сервис
   читает профиль заново непосредственно перед записью и правит свежую копию.
   Тест: Task 5, `TestCreateUsesFreshProfile`.
3. **Пир, заведённый вручную**: без PSK, с битым ключом, с нечисловым
   `email` — список не падает, пир показывается как `managed=false`, конфиг на
   него — 409. Тест: Task 5, `TestClientsWithManualPeers`.
4. **Подсеть закончилась** — понятная ошибка 409, а не паника и не повтор
   адреса. Тест: Task 2, `TestNextFreeAddressExhausted`; Task 6,
   `TestCreateMapsConflict`.
5. **Сессия панели истекла посреди работы** — 401 от панели доходит до
   страницы как 401, и страница уводит на вход. Тест: Task 6,
   `TestPanelUnauthorizedIsPassedThrough`.

---

## Структура файлов

```text
cmd/remnawave-wg-manager/main.go        конфиг из окружения, сборка, HTTP-сервер, healthcheck
internal/wgkey/wgkey.go                 ключи X25519, PSK, вывод ключа клиента
internal/profile/profile.go             чистые функции над JSON конфига профиля
internal/wgconf/wgconf.go               текст .conf клиента
internal/wgconf/qrsvg.go                QR-код в SVG
internal/panel/panel.go                 клиент API панели
internal/clients/clients.go             сценарии: инбаунды, клиенты, создание, удаление, конфиг
internal/httpapi/httpapi.go             REST, авторизация, заголовки безопасности, статика
internal/mcpserver/mcpserver.go         MCP-инструменты поверх clients
internal/web/web.go                     embed статики
internal/web/static/                    index.html, app.js, style.css, fonts/, OFL.txt
Containerfile, compose.example.yaml, deploy/nginx.example.conf
.golangci.yaml, Makefile, .github/workflows/ci.yml, README.md
```

---

### Task 0: Проверка привязки пира к пользователю панели (стенд)

Без кода. Отвечает на вопросы раздела «Статистика трафика» документа до того,
как на них опирается Task 5. Стенд: панель и нода Remnawave в контейнерах
(OrbStack), нода с WireGuard-инбаундом, клиент WireGuard из Xray.

**Files:**
- Modify: `docs/design.md` (раздел «Статистика трафика» — результат проверки)

- [ ] **Step 1: Завести пользователя панели без сквадов**

```bash
curl -s -X POST "$PANEL/api/users" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"wgprobe","expireAt":"2099-01-01T00:00:00.000Z"}' | jq '.response | {id, username, status}'
```

Ожидание: 201 и числовой `id`. Если панель требует сквад — записать это и
повторить с `activeInternalSquads: []`.

- [ ] **Step 2: Проверить эндпоинты, на которые опирается план**

```bash
curl -s "$PANEL/api/users/<id>" -H "Authorization: Bearer $TOKEN" | jq '.response.username'
curl -s "$PANEL/api/users/by-username/wgprobe" -H "Authorization: Bearer $TOKEN" | jq '.response.id'
curl -s "$PANEL/api/config-profiles" -H "Authorization: Bearer $TOKEN" | jq '.response.configProfiles[].name'
```

Ожидание: все три отвечают 200. Если пути другие — записать фактические и
исправить их в Task 4 до начала Task 4.

- [ ] **Step 3: Добавить пира с `email` = `id` и прогнать трафик**

В профиле стенда в `settings.peers` WireGuard-инбаунда добавить пира с
`"email": "<id>"`, поднять клиент WireGuard с его ключом и скачать через
туннель 50 МБ.

- [ ] **Step 4: Убедиться, что панель засчитала трафик**

```bash
curl -s "$PANEL/api/users/<id>" -H "Authorization: Bearer $TOKEN" | jq '.response.userTraffic.usedTrafficBytes'
```

Ожидание: не меньше 50 000 000 через 1–2 минуты.

- [ ] **Step 5: Проверить, что нода не трогает пира при событиях пользователя**

Отключить, включить, сменить срок, удалить пользователя в панели. После
каждого действия: пир остаётся в конфиге профиля, туннель клиента работает,
в логе ноды нет ошибок про этого пользователя.

- [ ] **Step 6: Записать результат в `docs/design.md`**

В «Статистика трафика» заменить список «Проверить до реализации» на итоги:
что подтвердилось, что нет, фактические пути API. Если привязка не работает —
записать, что `email` становится именем клиента, и в Task 5 заменить
разрешение пользователя на проверку имени по регулярному выражению из
Global Constraints.

- [ ] **Step 7: Коммит**

```bash
git add docs/design.md
git commit --signoff --message "docs(design): record panel-user binding check"
```

---

### Task 1: Ключи WireGuard и каркас модуля

**Files:**
- Create: `go.mod`, `.golangci.yaml`, `Makefile`, `.github/workflows/ci.yml`
- Create: `internal/wgkey/wgkey.go`
- Test: `internal/wgkey/wgkey_test.go`

**Interfaces:**
- Produces:
  - `type Key [32]byte`; `func ParseKey(s string) (Key, error)`; `func (k Key) String() string`
  - `func PublicKey(private Key) (Key, error)`
  - `func NewPSK() (Key, error)`
  - `func DeriveClient(server, psk Key, email string) (Key, error)`

- [ ] **Step 1: Каркас модуля**

```bash
go mod init github.com/kroticw/remnawave-wg-manager
go mod edit -go=1.27
```

`.golangci.yaml`:

```yaml
version: "2"
linters:
  default: standard
  enable:
    - gosec
    - errorlint
    - revive
    - misspell
    - bodyclose
    - noctx
formatters:
  enable:
    - gofmt
    - goimports
```

`Makefile`:

```makefile
.PHONY: test lint build
test:
	go test -race -count=1 ./...
lint:
	golangci-lint run
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remnawave-wg-manager ./cmd/remnawave-wg-manager
```

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [master]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - run: go test -race -count=1 ./...
      - uses: golangci/golangci-lint-action@v8
```

Перед коммитом проверить актуальные мажорные версии этих actions и
`golangci-lint` по их репозиториям и поправить номера.

- [ ] **Step 2: Тесты**

```go
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
```

- [ ] **Step 3: Убедиться, что тесты падают**

Run: `go test ./internal/wgkey/`
Expected: FAIL, `undefined: Key`.

- [ ] **Step 4: Реализация**

```go
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
```

- [ ] **Step 5: Тесты и линтер**

Run: `go test -race ./internal/wgkey/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 6: Коммит**

```bash
git add go.mod .golangci.yaml Makefile .github/workflows/ci.yml internal/wgkey
git commit --signoff --message "feat(wgkey): add WireGuard keys and client key derivation"
```

---

### Task 2: Правка пиров в конфиге профиля

**Files:**
- Create: `internal/profile/profile.go`
- Test: `internal/profile/profile_test.go`

**Interfaces:**
- Produces:
  - `type Peer struct { Email, PublicKey, PreSharedKey string; AllowedIPs []string }`
  - `type Inbound struct { Tag string; Port int; SecretKey string; Address []string; Peers []Peer }`
  - `var ErrNotFound, ErrConflict, ErrInvalid error`
  - `func WireGuardInbounds(cfg map[string]any) []Inbound`
  - `func FindInbound(cfg map[string]any, tag string) (Inbound, error)`
  - `func Subnet(in Inbound, prefixLen int) (netip.Prefix, netip.Addr, error)` — подсеть и адрес сервера
  - `func NextFreeAddress(in Inbound, prefixLen int) (netip.Addr, error)`
  - `func FreeCount(in Inbound, prefixLen int) (int, error)`
  - `func AddPeer(cfg map[string]any, tag string, p Peer) (map[string]any, error)`
  - `func RemovePeer(cfg map[string]any, tag, email string) (map[string]any, error)`

- [ ] **Step 1: Тесты**

```go
package profile

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
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
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sampleConfig), &cfg); err != nil {
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
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/profile/`
Expected: FAIL, `undefined: WireGuardInbounds`.

- [ ] **Step 3: Реализация**

```go
// Package profile reads and edits WireGuard peers inside a Remnawave config
// profile, keeping every other part of the configuration untouched.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

type Peer struct {
	Email        string   `json:"email"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
}

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
	return netip.Prefix{}, netip.Addr{}, fmt.Errorf("cannot infer subnet of %q: %w", in.Tag, ErrInvalid)
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

func FreeCount(in Inbound, prefixLen int) (int, error) {
	f, err := free(in, prefixLen)
	return len(f), err
}

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
```

`json.Marshal` и `Unmarshal` через `map[string]any` превращают числа в
`float64`, а `TestAddPeerPreservesUnrelatedFields` сравнивает с конфигом,
прочитанным тем же способом, поэтому сравнение честное. Если тест ловит
изменение целых чисел при отправке в панель, — переключить декодирование на
`json.Decoder` с `UseNumber()` здесь и в Task 4.

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/profile/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add internal/profile
git commit --signoff --message "feat(profile): read and edit WireGuard peers in a config profile"
```

---

### Task 3: Клиентский `.conf` и QR

**Files:**
- Create: `internal/wgconf/wgconf.go`, `internal/wgconf/qrsvg.go`
- Test: `internal/wgconf/wgconf_test.go`

**Interfaces:**
- Produces:
  - `type Client struct { PrivateKey, Address, DNS string; MTU int; ServerPublicKey, PresharedKey, Endpoint string }`
  - `func Render(c Client) string`
  - `func QRSVG(text string) (string, error)`

- [ ] **Step 1: Тесты**

```go
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
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/wgconf/`
Expected: FAIL, `undefined: Render`.

- [ ] **Step 3: Реализация**

```bash
go get rsc.io/qr@v0.2.0
```

`internal/wgconf/wgconf.go`:

```go
// Package wgconf renders WireGuard client configurations.
package wgconf

import (
	"fmt"
	"strings"
)

type Client struct {
	PrivateKey      string
	Address         string
	DNS             string
	MTU             int
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string
}

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
```

`internal/wgconf/qrsvg.go`:

```go
package wgconf

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

const quietZone = 4

// QRSVG renders text as a QR code in SVG, one path for all dark modules.
func QRSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("qr encode: %w", err)
	}
	size := code.Size + 2*quietZone
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quietZone, y+quietZone)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`+
		`<rect width="100%%" height="100%%" fill="#fff"/><path d="%s" fill="#000"/></svg>`, size, size, path.String()), nil
}
```

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/wgconf/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add go.mod go.sum internal/wgconf
git commit --signoff --message "feat(wgconf): render client configuration and QR code"
```

---

### Task 4: Клиент API панели

Пути и поля сверить с результатом Task 0 до начала.

**Files:**
- Create: `internal/panel/panel.go`
- Test: `internal/panel/panel_test.go`

**Interfaces:**
- Produces:
  - `type Credentials struct { Token string; Browser bool }`
  - `type Error struct { Status int; Body string }` + `func (e *Error) Error() string`
  - `type Profile struct { UUID, Name string; Config map[string]any; NodeUUIDs []string }`
  - `type User struct { ID int64; Username string }`
  - `type Client struct { BaseURL string; HTTP *http.Client; Forwarded bool }`
  - методы `ListProfiles(ctx, cred) ([]Profile, error)`, `GetProfile(ctx, cred, uuid) (Profile, error)`,
    `UpdateProfileConfig(ctx, cred, uuid string, cfg map[string]any) error`,
    `NodeAddress(ctx, cred, uuid) (string, error)`, `GetUser(ctx, cred, id int64) (User, error)`,
    `GetUserByUsername(ctx, cred, name string) (User, error)`, `CreateUser(ctx, cred, name string) (User, error)`

- [ ] **Step 1: Тесты**

```go
package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeadersForBrowserToken(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"response":{"total":0,"configProfiles":[]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Forwarded: true}
	if _, err := c.ListProfiles(context.Background(), Credentials{Token: "jwt", Browser: true}); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer jwt" || got.Get("X-Remnawave-Client-Type") != "browser" {
		t.Fatalf("headers %v", got)
	}
	if got.Get("X-Forwarded-Proto") != "https" || got.Get("X-Forwarded-For") == "" {
		t.Fatalf("forwarded headers missing: %v", got)
	}
}

func TestNoClientTypeForAPIToken(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"response":{"total":0,"configProfiles":[]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, _ = c.ListProfiles(context.Background(), Credentials{Token: "api"})
	if got.Get("X-Remnawave-Client-Type") != "" {
		t.Fatal("API token must not send the browser client type")
	}
}

func TestErrorStatusIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := c.GetProfile(context.Background(), Credentials{Token: "x"}, "u")
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized {
		t.Fatalf("err %v, want *Error with 401", err)
	}
}

func TestUpdateProfileConfigBody(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/config-profiles" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"response":{}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if err := c.UpdateProfileConfig(context.Background(), Credentials{Token: "x"}, "u1", map[string]any{"a": 1.0}); err != nil {
		t.Fatal(err)
	}
	if body["uuid"] != "u1" || body["config"].(map[string]any)["a"] != 1.0 {
		t.Fatalf("body %v", body)
	}
}

func TestGetProfileParsesNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"uuid":"u1","name":"p","config":{"inbounds":[]},"nodes":[{"uuid":"n1","name":"node"}]}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	p, err := c.GetProfile(context.Background(), Credentials{Token: "x"}, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "p" || len(p.NodeUUIDs) != 1 || p.NodeUUIDs[0] != "n1" || p.Config == nil {
		t.Fatalf("profile %+v", p)
	}
}

func TestCreateUser(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"response":{"id":77,"username":"alice"}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	u, err := c.CreateUser(context.Background(), Credentials{Token: "x"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != 77 || body["username"] != "alice" || body["expireAt"] == nil {
		t.Fatalf("user %+v body %v", u, body)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/panel/`
Expected: FAIL, `undefined: Client`.

- [ ] **Step 3: Реализация**

```go
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

type Credentials struct {
	Token   string
	Browser bool
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("panel responded %d: %s", e.Status, e.Body)
}

type Profile struct {
	UUID      string
	Name      string
	Config    map[string]any
	NodeUUIDs []string
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

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
	defer resp.Body.Close()
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

func (c *Client) GetProfile(ctx context.Context, cred Credentials, uuid string) (Profile, error) {
	var r rawProfile
	if err := c.do(ctx, cred, http.MethodGet, "/api/config-profiles/"+url.PathEscape(uuid), nil, &r); err != nil {
		return Profile{}, err
	}
	return r.profile(), nil
}

func (c *Client) UpdateProfileConfig(ctx context.Context, cred Credentials, uuid string, cfg map[string]any) error {
	body := map[string]any{"uuid": uuid, "config": cfg}
	return c.do(ctx, cred, http.MethodPatch, "/api/config-profiles", body, nil)
}

func (c *Client) NodeAddress(ctx context.Context, cred Credentials, uuid string) (string, error) {
	var r struct {
		Address string `json:"address"`
	}
	if err := c.do(ctx, cred, http.MethodGet, "/api/nodes/"+url.PathEscape(uuid), nil, &r); err != nil {
		return "", err
	}
	return r.Address, nil
}

func (c *Client) GetUser(ctx context.Context, cred Credentials, id int64) (User, error) {
	var u User
	err := c.do(ctx, cred, http.MethodGet, "/api/users/"+strconv.FormatInt(id, 10), nil, &u)
	return u, err
}

func (c *Client) GetUserByUsername(ctx context.Context, cred Credentials, name string) (User, error) {
	var u User
	err := c.do(ctx, cred, http.MethodGet, "/api/users/by-username/"+url.PathEscape(name), nil, &u)
	return u, err
}

func (c *Client) CreateUser(ctx context.Context, cred Credentials, name string) (User, error) {
	var u User
	body := map[string]any{"username": name, "expireAt": farFuture}
	err := c.do(ctx, cred, http.MethodPost, "/api/users", body, &u)
	return u, err
}
```

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/panel/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add internal/panel
git commit --signoff --message "feat(panel): add a minimal Remnawave panel API client"
```

---

### Task 5: Сценарии работы с клиентами

**Files:**
- Create: `internal/clients/clients.go`
- Test: `internal/clients/clients_test.go`

**Interfaces:**
- Consumes: `wgkey.*` (Task 1), `profile.*` (Task 2), `wgconf.*` (Task 3), `panel.Credentials`, `panel.Profile`, `panel.User`, `panel.Error` (Task 4).
- Produces:
  - `type Panel interface` с методами клиента панели из Task 4
  - `type Manager struct { Panel Panel; SubnetPrefix int; EndpointHost, DNS string; MTU int }`
  - `type InboundInfo struct { Profile, Tag string; Port int; Subnet, Endpoint string; Free int }`
  - `type ClientInfo struct { Email, Username, Address string; Managed bool }`
  - `func (m *Manager) Inbounds(ctx, cred) ([]InboundInfo, error)`
  - `func (m *Manager) Clients(ctx, cred, profile, tag string) ([]ClientInfo, error)`
  - `func (m *Manager) Create(ctx, cred, profile, tag, user, address string) (ClientInfo, error)`
  - `func (m *Manager) Delete(ctx, cred, profile, tag, email string) error`
  - `func (m *Manager) Config(ctx, cred, profile, tag, email string) (string, error)`
  - `var ErrNotManaged error` — конфиг для пира, ключ которого не выводится

- [ ] **Step 1: Тесты с поддельной панелью**

```go
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
	cfg      map[string]any
	users    map[int64]string
	nextID   int64
	updates  int
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
	f := newFake(t, `[]`)
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
	f := newFake(t, `[]`)
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
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/clients/`
Expected: FAIL, `undefined: Manager`.

- [ ] **Step 3: Реализация**

```go
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

var ErrNotManaged = errors.New("client key is not managed by this service")

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

type Panel interface {
	ListProfiles(ctx context.Context, cred panel.Credentials) ([]panel.Profile, error)
	GetProfile(ctx context.Context, cred panel.Credentials, uuid string) (panel.Profile, error)
	UpdateProfileConfig(ctx context.Context, cred panel.Credentials, uuid string, cfg map[string]any) error
	NodeAddress(ctx context.Context, cred panel.Credentials, uuid string) (string, error)
	GetUser(ctx context.Context, cred panel.Credentials, id int64) (panel.User, error)
	GetUserByUsername(ctx context.Context, cred panel.Credentials, name string) (panel.User, error)
	CreateUser(ctx context.Context, cred panel.Credentials, name string) (panel.User, error)
}

type Manager struct {
	Panel        Panel
	SubnetPrefix int
	EndpointHost string
	DNS          string
	MTU          int

	mu sync.Mutex
}

type InboundInfo struct {
	Profile  string `json:"profile"`
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Subnet   string `json:"subnet"`
	Endpoint string `json:"endpoint"`
	Free     int    `json:"free"`
}

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
		if len(p.NodeUUIDs) == 0 {
			return "", fmt.Errorf("profile %q has no nodes: %w", p.Name, profile.ErrInvalid)
		}
		addr, err := m.Panel.NodeAddress(ctx, cred, p.NodeUUIDs[0])
		if err != nil {
			return "", err
		}
		host = addr
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

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
```

`net.JoinHostPort` нужен ради IPv6-адреса ноды: он берёт адрес в скобки.

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/clients/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add internal/clients
git commit --signoff --message "feat(clients): implement listing, creation, removal and configs"
```

---

### Task 6: REST API, авторизация и заголовки безопасности

**Files:**
- Create: `internal/httpapi/httpapi.go`
- Test: `internal/httpapi/httpapi_test.go`

**Interfaces:**
- Consumes: `clients.Manager`, `clients.ErrNotManaged`, `profile.Err*`, `panel.Error`, `wgconf.QRSVG`.
- Produces:
  - `type Service interface` с методами `Inbounds`, `Clients`, `Create`, `Delete`, `Config` из Task 5
  - `func New(svc Service, basePath, loginPath string, static fs.FS) http.Handler`
  - `func SecurityHeaders(next http.Handler) http.Handler`
  - `func StatusFor(err error) int`

- [ ] **Step 1: Тесты**

```go
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
)

type fakeSvc struct {
	err     error
	gotCred panel.Credentials
}

func (f *fakeSvc) Inbounds(_ context.Context, c panel.Credentials) ([]clients.InboundInfo, error) {
	f.gotCred = c
	return []clients.InboundInfo{{Profile: "p", Tag: "wg"}}, f.err
}
func (f *fakeSvc) Clients(context.Context, panel.Credentials, string, string) ([]clients.ClientInfo, error) {
	return []clients.ClientInfo{{Email: "76"}}, f.err
}
func (f *fakeSvc) Create(_ context.Context, _ panel.Credentials, _, _, user, _ string) (clients.ClientInfo, error) {
	return clients.ClientInfo{Email: "76", Username: user}, f.err
}
func (f *fakeSvc) Delete(context.Context, panel.Credentials, string, string, string) error { return f.err }
func (f *fakeSvc) Config(context.Context, panel.Credentials, string, string, string) (string, error) {
	return "[Interface]\n", f.err
}

var static = fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRequiresToken(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", w.Code)
	}
}

func TestBrowserCredentials(t *testing.T) {
	svc := &fakeSvc{}
	h := New(svc, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "jwt", ""); w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	if svc.gotCred.Token != "jwt" || !svc.gotCred.Browser {
		t.Fatalf("cred %+v", svc.gotCred)
	}
}

func TestPanelUnauthorizedIsPassedThrough(t *testing.T) {
	h := New(&fakeSvc{err: &panel.Error{Status: 401}}, "/wg", "/auth/login", static)
	if w := do(t, h, http.MethodGet, "/wg/api/inbounds", "expired", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", w.Code)
	}
}

func TestStatusFor(t *testing.T) {
	cases := map[error]int{
		fmt.Errorf("x: %w", profile.ErrNotFound): 404,
		fmt.Errorf("x: %w", profile.ErrConflict): 409,
		fmt.Errorf("x: %w", profile.ErrInvalid):  400,
		fmt.Errorf("x: %w", clients.ErrNotManaged): 409,
		&panel.Error{Status: 403}:                403,
		&panel.Error{Status: 500}:                502,
		errors.New("boom"):                       502,
	}
	for err, want := range cases {
		if got := StatusFor(err); got != want {
			t.Errorf("%v: %d, want %d", err, got, want)
		}
	}
}

func TestCreateMapsConflict(t *testing.T) {
	h := New(&fakeSvc{err: fmt.Errorf("full: %w", profile.ErrConflict)}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodPost, "/wg/api/inbounds/p/wg/clients", "jwt", `{"user":"alice"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code %d", w.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] == "" {
		t.Fatalf("no error message: %s", w.Body)
	}
}

func TestConfigDownload(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/inbounds/p/wg/clients/76/config", "jwt", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), `filename="wg-76.conf"`) {
		t.Fatalf("code %d headers %v", w.Code, w.Header())
	}
}

func TestQR(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/inbounds/p/wg/clients/76/qr.svg", "jwt", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("code %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/", "", "")
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "font-src 'self'", "img-src 'self' data: blob:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q misses %q", csp, want)
		}
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers %v", w.Header())
	}
}

func TestMetaIsPublic(t *testing.T) {
	h := New(&fakeSvc{}, "/wg", "/auth/login", static)
	w := do(t, h, http.MethodGet, "/wg/api/meta", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"/auth/login"`) {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/httpapi/`
Expected: FAIL, `undefined: New`.

- [ ] **Step 3: Реализация**

```go
// Package httpapi serves the REST API and the static page.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/profile"
	"github.com/kroticw/remnawave-wg-manager/internal/wgconf"
)

// blob: lets the page show the QR code fetched with the Authorization header.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

type Service interface {
	Inbounds(ctx context.Context, cred panel.Credentials) ([]clients.InboundInfo, error)
	Clients(ctx context.Context, cred panel.Credentials, profile, tag string) ([]clients.ClientInfo, error)
	Create(ctx context.Context, cred panel.Credentials, profile, tag, user, address string) (clients.ClientInfo, error)
	Delete(ctx context.Context, cred panel.Credentials, profile, tag, email string) error
	Config(ctx context.Context, cred panel.Credentials, profile, tag, email string) (string, error)
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func StatusFor(err error) int {
	var pe *panel.Error
	switch {
	case errors.As(err, &pe) && (pe.Status == http.StatusUnauthorized || pe.Status == http.StatusForbidden):
		return pe.Status
	case errors.As(err, &pe) && pe.Status == http.StatusNotFound:
		return http.StatusNotFound
	case errors.Is(err, profile.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, profile.ErrConflict), errors.Is(err, clients.ErrNotManaged):
		return http.StatusConflict
	case errors.Is(err, profile.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, StatusFor(err), map[string]string{"error": err.Error()})
}

func credentials(r *http.Request) (panel.Credentials, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return panel.Credentials{}, false
	}
	return panel.Credentials{Token: token, Browser: true}, true
}

func authed(fn func(http.ResponseWriter, *http.Request, panel.Credentials)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, ok := credentials(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}
		fn(w, r, cred)
	}
}

func New(svc Service, basePath, loginPath string, static fs.FS) http.Handler {
	mux := http.NewServeMux()
	b := strings.TrimSuffix(basePath, "/")

	mux.Handle("GET "+b+"/", http.StripPrefix(b+"/", http.FileServerFS(static)))
	mux.HandleFunc("GET "+b+"/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET "+b+"/api/meta", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"loginPath": loginPath})
	})
	mux.HandleFunc("GET "+b+"/api/inbounds", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		list, err := svc.Inbounds(r.Context(), c)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}))
	const clientsPath = "/api/inbounds/{profile}/{tag}/clients"
	mux.HandleFunc("GET "+b+clientsPath, authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		list, err := svc.Clients(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}))
	mux.HandleFunc("POST "+b+clientsPath, authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		var req struct {
			User    string `json:"user"`
			Address string `json:"address"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		ci, err := svc.Create(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), req.User, req.Address)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, ci)
	}))
	mux.HandleFunc("DELETE "+b+clientsPath+"/{email}", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		if err := svc.Delete(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email")); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET "+b+clientsPath+"/{email}/config", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		conf, err := svc.Config(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email"))
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", `attachment; filename="wg-`+r.PathValue("email")+`.conf"`)
		_, _ = w.Write([]byte(conf))
	}))
	mux.HandleFunc("GET "+b+clientsPath+"/{email}/qr.svg", authed(func(w http.ResponseWriter, r *http.Request, c panel.Credentials) {
		conf, err := svc.Config(r.Context(), c, r.PathValue("profile"), r.PathValue("tag"), r.PathValue("email"))
		if err != nil {
			writeErr(w, err)
			return
		}
		svg, err := wgconf.QRSVG(conf)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(svg))
	}))
	return SecurityHeaders(mux)
}
```

`email` попадает в имя файла только после того, как `Config` нашёл пира с
таким `email` в профиле; на любое другое значение ответ — 404 до записи
заголовка.

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/httpapi/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add internal/httpapi
git commit --signoff --message "feat(httpapi): add REST API, auth pass-through and security headers"
```

---

### Task 7: Страница в стиле панели

**Files:**
- Create: `internal/web/web.go`
- Create: `internal/web/static/index.html`, `internal/web/static/app.js`, `internal/web/static/style.css`
- Create: `internal/web/static/fonts/` (Montserrat 400 и 600, латиница и кириллица, `woff2`), `internal/web/static/fonts/OFL.txt`
- Test: `internal/web/web_test.go`

**Interfaces:**
- Consumes: REST из Task 6 (относительные пути `api/...` от `/wg/`).
- Produces: `var Static fs.FS` — содержимое `static/` для `httpapi.New`.

- [ ] **Step 1: Тесты на статику**

```go
package web

import (
	"io/fs"
	"strings"
	"testing"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(Static, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNoInnerHTML(t *testing.T) {
	if strings.Contains(read(t, "app.js"), "innerHTML") || strings.Contains(read(t, "app.js"), "insertAdjacentHTML") {
		t.Fatal("app.js must not use innerHTML or insertAdjacentHTML")
	}
}

func TestNoInlineScriptsOrExternalResources(t *testing.T) {
	html := read(t, "index.html")
	for _, bad := range []string{"<script>", "onclick=", "http://", "https://", "style=\""} {
		if strings.Contains(html, bad) {
			t.Fatalf("index.html contains %q", bad)
		}
	}
}

func TestFontsAndLicensePresent(t *testing.T) {
	for _, name := range []string{"fonts/OFL.txt", "fonts/montserrat-latin-400.woff2", "fonts/montserrat-cyrillic-600.woff2"} {
		if _, err := fs.Stat(Static, name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/web/`
Expected: FAIL, `undefined: Static`.

- [ ] **Step 3: Шрифты и иконки**

```bash
mkdir -p internal/web/static/fonts
for s in latin cyrillic; do for w in 400 600; do
  curl -fsSL -o internal/web/static/fonts/montserrat-$s-$w.woff2 \
    "https://cdn.jsdelivr.net/fontsource/fonts/montserrat@latest/$s-$w-normal.woff2"
done; done
curl -fsSL -o internal/web/static/fonts/OFL.txt \
  https://raw.githubusercontent.com/JulietaUla/Montserrat/master/OFL.txt
for i in plus trash download qrcode logout refresh; do
  curl -fsSL "https://cdn.jsdelivr.net/npm/@tabler/icons@latest/icons/outline/$i.svg"; echo
done > tabler-icons.tmp.txt   # temporary, do not commit
```

Иконки вставить в `index.html` как `<symbol id="i-<имя>">` внутри скрытого
`<svg>`, используя `<path>` из скачанных файлов; на кнопках —
`<svg><use href="#i-plus"/></svg>`. Лицензию Tabler (MIT) упомянуть в
`README.md`.

- [ ] **Step 4: `web.go`**

```go
// Package web embeds the static page.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var embedded embed.FS

// Static is the page served under the base path.
var Static, _ = fs.Sub(embedded, "static")
```

- [ ] **Step 5: `style.css` — тема панели**

```css
@font-face { font-family: Montserrat; font-weight: 400; font-display: swap;
  src: url(fonts/montserrat-latin-400.woff2) format("woff2"); unicode-range: U+0000-00FF, U+2000-206F; }
@font-face { font-family: Montserrat; font-weight: 400; font-display: swap;
  src: url(fonts/montserrat-cyrillic-400.woff2) format("woff2"); unicode-range: U+0400-04FF; }
@font-face { font-family: Montserrat; font-weight: 600; font-display: swap;
  src: url(fonts/montserrat-latin-600.woff2) format("woff2"); unicode-range: U+0000-00FF, U+2000-206F; }
@font-face { font-family: Montserrat; font-weight: 600; font-display: swap;
  src: url(fonts/montserrat-cyrillic-600.woff2) format("woff2"); unicode-range: U+0400-04FF; }

:root {
  --dark-0: #c9d1d9; --dark-1: #b1bac4; --dark-2: #8b949e; --dark-3: #6e7681;
  --dark-4: #484f58; --dark-5: #30363d; --dark-6: #21262d; --dark-7: #161b22;
  --dark-8: #0d1117; --dark-9: #010409;
  --cyan: #0c8599; --cyan-light: rgba(21, 170, 191, 0.15); --cyan-text: #66d9e8;
  --red-light: rgba(250, 82, 82, 0.15); --red-text: #ff8787;
  --radius: 8px;
  --font: Montserrat, "Apple Color Emoji", sans-serif;
  --mono: "Fira Mono", ui-monospace, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100vh; background: var(--dark-7); color: var(--dark-0);
  font-family: var(--font); font-size: 14px; -webkit-font-smoothing: antialiased; }
h1, h2, h3 { font-weight: 600; margin: 0; }
header { display: flex; align-items: center; gap: 12px; padding: 16px 24px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08); }
header h1 { font-size: 18px; flex: 1; }
main { max-width: 1100px; margin: 0 auto; padding: 24px; display: grid; gap: 16px; }
.card { background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius); padding: 16px; animation: fadeIn 200ms linear both; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.btn { display: inline-flex; align-items: center; gap: 6px; height: 34px; padding: 0 14px;
  border: 0; border-radius: var(--radius); font: 600 13px var(--font); cursor: pointer;
  background: var(--cyan-light); color: var(--cyan-text); transition: all 0.2s ease; }
.btn:hover { filter: brightness(1.2); }
.btn.danger { background: var(--red-light); color: var(--red-text); }
.btn svg { width: 16px; height: 16px; stroke: currentColor; fill: none; stroke-width: 2; }
select, input { height: 34px; padding: 0 10px; border-radius: var(--radius);
  border: 1px solid var(--dark-4); background: var(--dark-6); color: var(--dark-0); font: 14px var(--font); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--dark-5); }
th { color: var(--dark-2); font-weight: 600; font-size: 12px; text-transform: uppercase; }
td.mono { font-family: var(--mono); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.badge.ok { background: var(--cyan-light); color: var(--cyan-text); }
.badge.muted { background: var(--dark-5); color: var(--dark-2); }
.actions { display: flex; gap: 8px; justify-content: flex-end; }
dialog { background: var(--dark-6); color: var(--dark-0); border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius); padding: 20px; max-width: 420px; }
dialog::backdrop { background: rgba(1, 4, 9, 0.6); }
.qr { background: #fff; border-radius: var(--radius); padding: 8px; width: 260px; }
.warn { color: var(--dark-2); font-size: 13px; }
.error { color: var(--red-text); }
.hidden { display: none; }
```

Значение `--cyan` — оттенок 8 палитры `cyan` Mantine; при реализации
сверить по исходникам `@mantine/core` 9 (`default-colors`) и поправить, если
отличается.

- [ ] **Step 6: `index.html`**

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WireGuard</title>
  <link rel="stylesheet" href="style.css">
  <script src="app.js" defer></script>
</head>
<body>
  <svg class="hidden" aria-hidden="true">
    <!-- symbols i-plus, i-trash, i-download, i-qrcode, i-logout, i-refresh из Step 3 -->
  </svg>
  <header>
    <h1>WireGuard</h1>
    <select id="inbound" aria-label="Инбаунд"></select>
    <button class="btn" id="refresh"><svg><use href="#i-refresh"/></svg>Обновить</button>
    <button class="btn" id="logout"><svg><use href="#i-logout"/></svg>Выйти</button>
  </header>
  <main>
    <section class="card">
      <div class="actions">
        <input id="user" placeholder="id или имя пользователя панели" autocomplete="off">
        <button class="btn" id="add"><svg><use href="#i-plus"/></svg>Добавить клиента</button>
      </div>
      <p class="warn">Любое изменение перезапускает Xray на нодах профиля: соединения через ноды прервутся на пару секунд.</p>
      <p class="error" id="error"></p>
    </section>
    <section class="card">
      <table>
        <thead><tr><th>Пользователь</th><th>email</th><th>Адрес</th><th>Ключ</th><th></th></tr></thead>
        <tbody id="clients"></tbody>
      </table>
    </section>
  </main>
  <dialog id="confirm">
    <h3>Удалить клиента?</h3>
    <p id="confirm-text"></p>
    <p class="warn">Xray на нодах профиля перезапустится.</p>
    <div class="actions">
      <button class="btn" id="confirm-no">Отмена</button>
      <button class="btn danger" id="confirm-yes"><svg><use href="#i-trash"/></svg>Удалить</button>
    </div>
  </dialog>
  <dialog id="qr-dialog">
    <h3 id="qr-title"></h3>
    <img class="qr" id="qr-img" alt="QR-код конфигурации">
    <div class="actions">
      <button class="btn" id="qr-download"><svg><use href="#i-download"/></svg>Скачать .conf</button>
      <button class="btn" id="qr-close">Закрыть</button>
    </div>
  </dialog>
</body>
</html>
```

Комментарий в `<svg>` заменить символами иконок из Step 3; тест
`TestNoInlineScriptsOrExternalResources` проверит, что внешних ссылок нет.
Атрибут `xmlns` у символов не нужен.

- [ ] **Step 7: `app.js`**

```js
"use strict";

const state = { token: "", inbound: null, loginPath: "/auth/login", pendingDelete: null, qrEmail: null };
const $ = (id) => document.getElementById(id);

function readToken() {
  try {
    const raw = localStorage.getItem("sessionStore");
    return raw ? (JSON.parse(raw).state || {}).token || "" : "";
  } catch {
    return "";
  }
}

async function api(path, options = {}) {
  const resp = await fetch("api/" + path, {
    ...options,
    headers: { "Authorization": "Bearer " + state.token, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (resp.status === 401 || resp.status === 403) {
    location.assign(state.loginPath);
    throw new Error("unauthorized");
  }
  if (!resp.ok) {
    let message = resp.statusText;
    try { message = (await resp.json()).error || message; } catch { /* not json */ }
    throw new Error(message);
  }
  return resp;
}

function showError(err) {
  $("error").textContent = err ? String(err.message || err) : "";
}

function inboundPath() {
  return "inbounds/" + encodeURIComponent(state.inbound.profile) + "/" + encodeURIComponent(state.inbound.tag) + "/clients";
}

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function iconButton(label, icon, className, onClick) {
  const b = document.createElement("button");
  b.className = "btn" + (className ? " " + className : "");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#i-" + icon);
  svg.appendChild(use);
  b.appendChild(svg);
  b.appendChild(document.createTextNode(label));
  b.addEventListener("click", onClick);
  return b;
}

async function loadClients() {
  showError(null);
  const body = $("clients");
  body.replaceChildren();
  if (!state.inbound) return;
  const list = await (await api(inboundPath())).json();
  for (const c of list) {
    const tr = document.createElement("tr");
    tr.appendChild(cell(c.username || "—"));
    tr.appendChild(cell(c.email, "mono"));
    tr.appendChild(cell(c.address, "mono"));
    const badge = document.createElement("span");
    badge.className = "badge " + (c.managed ? "ok" : "muted");
    badge.textContent = c.managed ? "сервис" : "вручную";
    const td = document.createElement("td");
    td.appendChild(badge);
    tr.appendChild(td);
    const actions = document.createElement("td");
    actions.className = "actions";
    if (c.managed) actions.appendChild(iconButton("QR", "qrcode", "", () => openQR(c)));
    actions.appendChild(iconButton("Удалить", "trash", "danger", () => askDelete(c)));
    tr.appendChild(actions);
    body.appendChild(tr);
  }
}

async function loadInbounds() {
  const list = await (await api("inbounds")).json();
  const select = $("inbound");
  select.replaceChildren();
  list.forEach((inb, i) => {
    const o = document.createElement("option");
    o.value = String(i);
    o.textContent = inb.profile + " / " + inb.tag + " — " + inb.endpoint + ", свободно " + inb.free;
    select.appendChild(o);
  });
  state.inbound = list[0] || null;
  select.onchange = () => { state.inbound = list[Number(select.value)]; loadClients().catch(showError); };
}

async function openQR(c) {
  state.qrEmail = c.email;
  $("qr-title").textContent = (c.username || c.email) + " — " + c.address;
  const svg = await (await api(inboundPath() + "/" + encodeURIComponent(c.email) + "/qr.svg")).blob();
  $("qr-img").src = URL.createObjectURL(svg);
  $("qr-dialog").showModal();
}

async function downloadConfig() {
  const resp = await api(inboundPath() + "/" + encodeURIComponent(state.qrEmail) + "/config");
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "wg-" + state.qrEmail + ".conf";
  a.click();
  URL.revokeObjectURL(url);
}

function askDelete(c) {
  state.pendingDelete = c;
  $("confirm-text").textContent = (c.username || c.email) + " (" + c.address + ")";
  $("confirm").showModal();
}

async function addClient() {
  const user = $("user").value.trim();
  if (!user) return;
  const resp = await api(inboundPath(), { method: "POST", body: JSON.stringify({ user }) });
  const c = await resp.json();
  $("user").value = "";
  await loadClients();
  await openQR(c);
}

async function main() {
  state.token = readToken();
  try {
    state.loginPath = (await (await fetch("api/meta")).json()).loginPath || state.loginPath;
  } catch { /* keep default */ }
  if (!state.token) {
    location.assign(state.loginPath);
    return;
  }
  $("refresh").addEventListener("click", () => loadClients().catch(showError));
  $("logout").addEventListener("click", () => location.assign(state.loginPath));
  $("add").addEventListener("click", () => addClient().catch(showError));
  $("confirm-no").addEventListener("click", () => $("confirm").close());
  $("confirm-yes").addEventListener("click", async () => {
    $("confirm").close();
    try {
      await api(inboundPath() + "/" + encodeURIComponent(state.pendingDelete.email), { method: "DELETE" });
      await loadClients();
    } catch (e) { showError(e); }
  });
  $("qr-close").addEventListener("click", () => $("qr-dialog").close());
  $("qr-download").addEventListener("click", () => downloadConfig().catch(showError));
  await loadInbounds();
  await loadClients();
}

main().catch(showError);
```

QR приходит как `blob:` URL: `<img src>` не умеет слать заголовок
`Authorization`, поэтому картинку забирает `fetch`. Для этого в CSP из Task 6
есть `blob:` в `img-src`.

- [ ] **Step 8: Тесты, линтер, ручная проверка вида**

Run: `go test -race ./internal/web/ ./internal/httpapi/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

Ручная проверка — в Task 10 на стенде, рядом с панелью.

- [ ] **Step 9: Коммит**

```bash
git add internal/web internal/httpapi
git commit --signoff --message "feat(web): add the management page styled after the panel"
```

---

### Task 8: MCP

**Files:**
- Create: `internal/mcpserver/mcpserver.go`
- Test: `internal/mcpserver/mcpserver_test.go`

**Interfaces:**
- Consumes: `httpapi.Service` (Task 6), `panel.Credentials`.
- Produces: `func Handler(svc httpapi.Service) http.Handler`

- [ ] **Step 1: Тесты через клиент SDK**

```go
package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
)

type fakeSvc struct{ cred panel.Credentials }

func (f *fakeSvc) Inbounds(_ context.Context, c panel.Credentials) ([]clients.InboundInfo, error) {
	f.cred = c
	return []clients.InboundInfo{{Profile: "p", Tag: "wg"}}, nil
}
func (f *fakeSvc) Clients(context.Context, panel.Credentials, string, string) ([]clients.ClientInfo, error) {
	return nil, nil
}
func (f *fakeSvc) Create(context.Context, panel.Credentials, string, string, string, string) (clients.ClientInfo, error) {
	return clients.ClientInfo{Email: "76"}, nil
}
func (f *fakeSvc) Delete(context.Context, panel.Credentials, string, string, string) error { return nil }
func (f *fakeSvc) Config(context.Context, panel.Credentials, string, string, string) (string, error) {
	return "[Interface]\n", nil
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestToolsAndAPITokenCredentials(t *testing.T) {
	svc := &fakeSvc{}
	srv := httptest.NewServer(Handler(svc))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{"api-token"}}}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = tool
	}
	for _, n := range []string{"wg_list_inbounds", "wg_list_clients", "wg_create_client", "wg_delete_client", "wg_get_client_config"} {
		if names[n] == nil {
			t.Fatalf("tool %s missing", n)
		}
	}
	if d := names["wg_delete_client"].Annotations.DestructiveHint; d == nil || !*d {
		t.Fatal("wg_delete_client must be destructive")
	}
	if !names["wg_list_clients"].Annotations.ReadOnlyHint {
		t.Fatal("wg_list_clients must be read-only")
	}

	if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "wg_list_inbounds", Arguments: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if svc.cred.Token != "api-token" || svc.cred.Browser {
		t.Fatalf("cred %+v, want API token without browser flag", svc.cred)
	}
}
```

Перед реализацией сверить имена `StreamableClientTransport`, его полей,
`ListTools` и `CallToolParams` по документации go-sdk v1.8.0 и при
расхождении поправить тест.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go get github.com/modelcontextprotocol/go-sdk@v1.8.0 && go test ./internal/mcpserver/`
Expected: FAIL, `undefined: Handler`.

- [ ] **Step 3: Реализация**

```go
// Package mcpserver exposes the WireGuard client operations as MCP tools.
package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/httpapi"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
)

const restartNote = " Changes rewrite the config profile and restart Xray on the profile's nodes, dropping their connections for a few seconds."

type inboundArgs struct {
	Profile string `json:"profile" jsonschema:"config profile name"`
	Tag     string `json:"tag" jsonschema:"WireGuard inbound tag"`
}

type createArgs struct {
	inboundArgs
	User    string `json:"user" jsonschema:"panel user id, or a new username to create"`
	Address string `json:"address,omitempty" jsonschema:"optional client address; the lowest free one by default"`
}

type clientArgs struct {
	inboundArgs
	Email string `json:"email" jsonschema:"peer email, the panel user id"`
}

type list[T any] struct {
	Items []T `json:"items"`
}

type configOut struct {
	Config string `json:"config"`
}

type done struct {
	OK bool `json:"ok"`
}

func cred(req *mcp.CallToolRequest) (panel.Credentials, error) {
	if req.Extra == nil || req.Extra.Header == nil {
		return panel.Credentials{}, errors.New("missing Authorization header")
	}
	token, ok := strings.CutPrefix(req.Extra.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return panel.Credentials{}, errors.New("missing bearer token")
	}
	return panel.Credentials{Token: token}, nil
}

func boolPtr(b bool) *bool { return &b }

func newServer(svc httpapi.Service) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "remnawave-wg-manager", Version: "v0.1.0"}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "wg_list_inbounds", Description: "List WireGuard inbounds in all config profiles.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, list[clients.InboundInfo], error) {
			c, err := cred(req)
			if err != nil {
				return nil, list[clients.InboundInfo]{}, err
			}
			items, err := svc.Inbounds(ctx, c)
			return nil, list[clients.InboundInfo]{Items: items}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_list_clients", Description: "List clients (peers) of a WireGuard inbound.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, a inboundArgs) (*mcp.CallToolResult, list[clients.ClientInfo], error) {
			c, err := cred(req)
			if err != nil {
				return nil, list[clients.ClientInfo]{}, err
			}
			items, err := svc.Clients(ctx, c, a.Profile, a.Tag)
			return nil, list[clients.ClientInfo]{Items: items}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_create_client", Description: "Create a WireGuard client bound to a panel user. Does not return the config." + restartNote,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false)}},
		func(ctx context.Context, req *mcp.CallToolRequest, a createArgs) (*mcp.CallToolResult, clients.ClientInfo, error) {
			c, err := cred(req)
			if err != nil {
				return nil, clients.ClientInfo{}, err
			}
			ci, err := svc.Create(ctx, c, a.Profile, a.Tag, a.User, a.Address)
			return nil, ci, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_delete_client", Description: "Delete a WireGuard client." + restartNote,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, a clientArgs) (*mcp.CallToolResult, done, error) {
			c, err := cred(req)
			if err != nil {
				return nil, done{}, err
			}
			err = svc.Delete(ctx, c, a.Profile, a.Tag, a.Email)
			return nil, done{OK: err == nil}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_get_client_config", Description: "Return the client .conf. It contains the client's PRIVATE KEY.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, a clientArgs) (*mcp.CallToolResult, configOut, error) {
			c, err := cred(req)
			if err != nil {
				return nil, configOut{}, err
			}
			conf, err := svc.Config(ctx, c, a.Profile, a.Tag, a.Email)
			return nil, configOut{Config: conf}, err
		})
	return s
}

// Handler serves MCP over Streamable HTTP.
func Handler(svc httpapi.Service) http.Handler {
	s := newServer(svc)
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
```

- [ ] **Step 4: Тесты и линтер**

Run: `go test -race ./internal/mcpserver/ && golangci-lint run`
Expected: `ok`, ноль замечаний.

- [ ] **Step 5: Коммит**

```bash
git add go.mod go.sum internal/mcpserver
git commit --signoff --message "feat(mcp): expose client operations as MCP tools"
```

---

### Task 9: Точка входа, конфигурация и healthcheck

**Files:**
- Create: `cmd/remnawave-wg-manager/main.go`
- Test: `cmd/remnawave-wg-manager/main_test.go`

**Interfaces:**
- Consumes: всё из Task 4–8, `web.Static`.
- Produces: `func loadConfig(getenv func(string) string) (config, error)`, бинарь с подкомандой `healthcheck`.

- [ ] **Step 1: Тесты конфигурации**

```go
package main

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(env(map[string]string{"PANEL_URL": "http://remnawave:3000"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.BasePath != "/wg" || c.LoginPath != "/auth/login" || c.MTU != 1380 || c.SubnetPrefix != 24 ||
		c.DNS != "1.1.1.1, 8.8.8.8" || c.Listen != ":8080" || !c.Forwarded {
		t.Fatalf("defaults %+v", c)
	}
}

func TestLoadConfigRequiresPanelURL(t *testing.T) {
	if _, err := loadConfig(env(nil)); err == nil {
		t.Fatal("PANEL_URL must be required")
	}
}

func TestLoadConfigRejectsBadNumbers(t *testing.T) {
	for _, kv := range [][2]string{{"CLIENT_MTU", "abc"}, {"SUBNET_PREFIX", "40"}, {"CLIENT_MTU", "100"}} {
		if _, err := loadConfig(env(map[string]string{"PANEL_URL": "http://x", kv[0]: kv[1]})); err == nil {
			t.Errorf("%s=%s must be rejected", kv[0], kv[1])
		}
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./cmd/remnawave-wg-manager/`
Expected: FAIL, `undefined: loadConfig`.

- [ ] **Step 3: Реализация**

```go
// Command remnawave-wg-manager serves the WireGuard client management page,
// REST API and MCP endpoint next to a Remnawave panel.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/httpapi"
	"github.com/kroticw/remnawave-wg-manager/internal/mcpserver"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/web"
)

type config struct {
	PanelURL     string
	BasePath     string
	LoginPath    string
	Listen       string
	EndpointHost string
	DNS          string
	MTU          int
	SubnetPrefix int
	Forwarded    bool
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intIn(getenv func(string) string, key string, def, lo, hi int) (int, error) {
	raw := getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < lo || v > hi {
		return 0, fmt.Errorf("%s must be an integer in [%d, %d], got %q", key, lo, hi, raw)
	}
	return v, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		PanelURL:     strings.TrimSuffix(getenv("PANEL_URL"), "/"),
		BasePath:     "/" + strings.Trim(or(getenv("BASE_PATH"), "/wg"), "/"),
		LoginPath:    or(getenv("LOGIN_PATH"), "/auth/login"),
		Listen:       or(getenv("LISTEN"), ":8080"),
		EndpointHost: getenv("ENDPOINT_HOST"),
		DNS:          or(getenv("CLIENT_DNS"), "1.1.1.1, 8.8.8.8"),
		Forwarded:    getenv("FORWARDED_HEADERS") != "false",
	}
	if c.PanelURL == "" {
		return c, errors.New("PANEL_URL is required")
	}
	var err error
	if c.MTU, err = intIn(getenv, "CLIENT_MTU", 1380, 1280, 1500); err != nil {
		return c, err
	}
	if c.SubnetPrefix, err = intIn(getenv, "SUBNET_PREFIX", 24, 16, 30); err != nil {
		return c, err
	}
	return c, nil
}

func healthcheck(listen string) int {
	port := listen[strings.LastIndex(listen, ":")+1:]
	base := "/" + strings.Trim(or(os.Getenv("BASE_PATH"), "/wg"), "/")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+base+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(or(os.Getenv("LISTEN"), ":8080")))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	pc := &panel.Client{BaseURL: cfg.PanelURL, HTTP: &http.Client{Timeout: 30 * time.Second}, Forwarded: cfg.Forwarded}
	mgr := &clients.Manager{Panel: pc, SubnetPrefix: cfg.SubnetPrefix, EndpointHost: cfg.EndpointHost, DNS: cfg.DNS, MTU: cfg.MTU}

	mux := http.NewServeMux()
	mux.Handle(cfg.BasePath+"/mcp", httpapi.SecurityHeaders(mcpserver.Handler(mgr)))
	mux.Handle("/", httpapi.New(mgr, cfg.BasePath, cfg.LoginPath, web.Static))

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.Listen, "base", cfg.BasePath, "panel", cfg.PanelURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Тесты, линтер, запуск**

Run: `go test -race ./... && golangci-lint run && make build`
Expected: `ok` по всем пакетам, ноль замечаний, бинарь `bin/remnawave-wg-manager`.

- [ ] **Step 5: Коммит**

```bash
git add cmd
git commit --signoff --message "feat: add entrypoint, configuration and healthcheck"
```

---

### Task 10: Образ, примеры развёртывания и сквозная проверка на стенде

**Files:**
- Create: `Containerfile`, `.containerignore`, `compose.example.yaml`, `deploy/nginx.example.conf`
- Modify: `.github/workflows/ci.yml` (сборка и публикация образа по тегу)
- Modify: `README.md`

- [ ] **Step 1: `Containerfile`**

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/remnawave-wg-manager ./cmd/remnawave-wg-manager

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/kroticw/remnawave-wg-manager" \
      org.opencontainers.image.description="WireGuard peer management for Remnawave" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/remnawave-wg-manager /remnawave-wg-manager
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/remnawave-wg-manager", "healthcheck"]
ENTRYPOINT ["/remnawave-wg-manager"]
```

Обе базовые ссылки закрепить по sha256: получить дайджесты
`docker buildx imagetools inspect golang:1.27-alpine` и
`docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot`
и дописать `@sha256:...`. `.containerignore`: `bin/`, `.git/`, `docs/`.

- [ ] **Step 2: `compose.example.yaml` и `deploy/nginx.example.conf`**

```yaml
services:
  remnawave-wg-manager:
    image: ghcr.io/kroticw/remnawave-wg-manager:latest
    container_name: remnawave-wg-manager
    restart: unless-stopped
    environment:
      PANEL_URL: http://remnawave:3000
      BASE_PATH: /wg
    networks: [remnawave-network]
networks:
  remnawave-network:
    external: true
```

```nginx
location /wg/ {
    proxy_pass http://remnawave-wg-manager:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;          # MCP Streamable HTTP uses server-sent events
    proxy_read_timeout 300s;
}
```

- [ ] **Step 3: Сборка образа под обе архитектуры**

Run: `docker buildx build --platform linux/amd64,linux/arm64 -t remnawave-wg-manager:dev -f Containerfile .`
Expected: сборка без ошибок.

- [ ] **Step 4: Сквозная проверка на стенде**

На стенде Task 0 (панель, нода, WireGuard-инбаунд) поднять контейнер в сети
панели и nginx с `location /wg/`. Проверить руками в браузере, после входа в
панель:

1. Страница `/wg/` открывается без входа в панель — переход на `/auth/login`.
2. После входа видны инбаунд и клиенты; вид совпадает с панелью (цвета,
   шрифт, кнопки) — сравнить скриншоты рядом.
3. Создание клиента по имени: появляется пользователь в панели, пир в
   профиле, QR и `.conf`; клиент WireGuard с этим конфигом поднимает туннель и
   ходит через него.
4. Скачивание `.conf` повторно даёт тот же текст.
5. Трафик клиента виден у пользователя в панели.
6. Удаление: пир исчезает из профиля, туннель перестаёт работать.
7. В консоли браузера нет ошибок CSP.
8. MCP: `claude mcp add --transport http wg http://<стенд>/wg/mcp --header "Authorization: Bearer <API-токен>"`,
   вызвать `wg_list_inbounds` и `wg_list_clients`.

Найденные расхождения — исправить в соответствующем пакете с тестом на
причину, отдельным коммитом.

- [ ] **Step 5: Публикация образа в CI**

В `.github/workflows/ci.yml` добавить job `image` на `push` тегов `v*`:
`docker/setup-qemu-action`, `docker/setup-buildx-action`,
`docker/login-action` (GHCR, `GITHUB_TOKEN`), `docker/build-push-action` с
`platforms: linux/amd64,linux/arm64` и тегами `${{ github.ref_name }}` и
`latest`; `permissions: packages: write`. Актуальные мажорные версии actions
проверить по их репозиториям.

- [ ] **Step 6: `README.md` (английский)**

Что это, ограничения (перезапуск Xray, вход через сессию панели и риск XSS,
ключи выводятся из профиля), переменные окружения из `docs/design.md`,
развёртывание по `compose.example.yaml` и `deploy/nginx.example.conf`,
подключение MCP, лицензии шрифта (OFL) и иконок (MIT).

- [ ] **Step 7: Коммит**

```bash
git add Containerfile .containerignore compose.example.yaml deploy .github/workflows/ci.yml README.md
git commit --signoff --message "build: add container image, deployment examples and docs"
```

---

### Task 11: Развёртывание у себя

Выполняется только после явного согласия оператора: меняет прод.

- [ ] **Step 1:** выпустить подписанный тег `v0.1.0` (`git tag --sign v0.1.0 --message "..."`), дождаться образа в GHCR.
- [ ] **Step 2:** на хосте панели — бэкап `compose`-файлов и конфига nginx, затем добавить сервис и `location /wg/`; `nginx -t` перед перезагрузкой.
- [ ] **Step 3:** пройти чек-лист Task 10 Step 4 на проде, начиная с чтения, без создания клиентов, пока оператор не подтвердит.
- [ ] **Step 4:** записать развёртывание в приватную базу знаний (адреса, пути, откат) — не в этот публичный репозиторий.
