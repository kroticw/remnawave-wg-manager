# remnawave-wg-manager

Web UI and MCP server to manage WireGuard peers of Xray WireGuard inbounds
in [Remnawave](https://github.com/remnawave) config profiles.

The panel does not manage WireGuard clients. This service runs next to the
panel, edits `settings.peers` of WireGuard inbounds through the panel API and
gives each client a ready `.conf` file and a QR code.

## How it works

- **No state.** The config profile in the panel is the only source of truth.
  The service stores nothing on disk and holds no secrets.
- **Keys are derived, not stored.** A client private key is derived from the
  inbound private key, the peer's pre-shared key and the peer email
  (HKDF-SHA256). The same config can be downloaded again at any time.
  Peers added by hand are listed as unmanaged; their configs cannot be
  rebuilt.
- **Traffic is counted by the panel.** The peer email is the id of a panel
  user, so the panel accounts the client's traffic to that user. Creating a
  client picks an existing user by id or creates a new one by name.
- **Same origin as the panel.** The page lives under the panel domain
  (`/wg/`) and reuses the panel login session. Every request goes to the
  panel with the admin's own token.

See [docs/design.md](docs/design.md) for the full design (in Russian).

## Limitations

- Every change rewrites the config profile, and the panel restarts Xray on
  all nodes of that profile. Connections through those nodes drop for a
  couple of seconds.
- Disabling, expiring or limiting a panel user does **not** stop its
  WireGuard peer. Remove the client to revoke access.
- Deleting a panel user leaves its peer in the profile; the service lists it
  without a user name.
- The page reads the panel session token from the browser. Any XSS on the
  panel domain can therefore use it. The page itself ships a strict CSP and
  renders user data as text only.

## Configuration

| Variable | Meaning | Default |
| --- | --- | --- |
| `PANEL_URL` | Panel API address inside the network | required |
| `BASE_PATH` | Path prefix of the service | `/wg` |
| `LOGIN_PATH` | Panel login page | `/auth/login` |
| `LISTEN` | Listen address | `:8080` |
| `SUBNET_PREFIX` | Client subnet length when the inbound has no `address` | `24` |
| `ENDPOINT_HOST` | Override the node address in client configs | node address |
| `CLIENT_DNS` | DNS in client configs | `1.1.1.1, 8.8.8.8` |
| `CLIENT_MTU` | MTU in client configs | `1380` |
| `FORWARDED_HEADERS` | Send `X-Forwarded-Proto: https` to the panel; set `false` to disable | `true` |

## Deployment

Run the container in the panel's Docker network
([compose.example.yaml](compose.example.yaml)) and route `/wg/` to it from the
reverse proxy in front of the panel
([deploy/nginx.example.conf](deploy/nginx.example.conf)).

Proxy to the container address, not to `127.0.0.1`: the MCP endpoint rejects
requests that arrive on a loopback address with a non-loopback `Host`
(DNS rebinding protection).

## MCP

The MCP endpoint is `<panel domain>/wg/mcp` (Streamable HTTP). It
authenticates with a panel API token passed as `Authorization: Bearer`.
Create the token in the panel with these scopes only:

- `config-profiles:read`, `config-profiles:write`
- `nodes:read`
- `users:read`, `users:write`

```bash
claude mcp add --transport http wg https://panel.example.com/wg/mcp \
  --header "Authorization: Bearer <API token>"
```

Tools: `wg_list_inbounds`, `wg_list_clients`, `wg_create_client`,
`wg_delete_client`, `wg_get_client_config`. The last one returns the client
private key.

## Development

```bash
make test
make lint
make build
```

## Third-party assets

- [Montserrat](https://github.com/JulietaUla/Montserrat) font, SIL Open Font
  License 1.1 ([internal/web/static/fonts/OFL.txt](internal/web/static/fonts/OFL.txt)).
- [Tabler Icons](https://github.com/tabler/tabler-icons), MIT License.

## License

[MIT](LICENSE)
