# host-my-mcp

One public, OAuth-protected **Streamable HTTP** MCP gateway in front of many local **stdio** MCP servers.

```text
MCP clients (Claude, ChatGPT, Cursor, MCP Inspector, …)
        │  https://mcp-ph.zocomputer.io/<server>
        ▼
┌─────────────────────────────────────────────┐
│ host-my-mcp                                 │
│  • OAuth 2.1 resource server (Auth0 tokens) │
│  • per-server / per-tool authorization      │
│  • Streamable HTTP ⇄ stdio bridge           │
│  • child-process supervision + audit log    │
└──────┬──────────────┬──────────────┬────────┘
       │ /omg         │ /toggl       │ /attn
       ▼              ▼              ▼
   omg mcp …      toggl-mcp       attn-mcp        (local stdio processes)
```

Each configured server is mounted on its own path **and** is its own OAuth
resource, so a token minted for `/omg` is useless at `/toggl`. Auth0 owns login
(Google via Auth0's social connection), consent and token issuance; the gateway
only validates tokens, authorizes operations, routes, and supervises.

Written in Rust on top of the official [`rmcp`](https://crates.io/crates/rmcp)
SDK (both the Streamable HTTP server side and the stdio client side), `axum`,
and `jsonwebtoken`. Single static binary; no runtime dependencies.

## Contents

- [Quick start (no auth, local)](#quick-start-no-auth-local)
- [Configuration](#configuration)
- [Auth0 setup walkthrough](#auth0-setup-walkthrough)
- [Deploying behind Zo](#deploying-behind-zo)
- [How requests are authorized](#how-requests-are-authorized)
- [Operations](#operations)
- [Design notes and limitations](#design-notes-and-limitations)

## Quick start (no auth, local)

```sh
cargo install --path .          # installs `host-my-mcp` and `host-my-mcp-echo`
# or, once published: cargo install host-my-mcp

cat > host-my-mcp.yaml <<'YAML'
public_url: http://127.0.0.1:8080
auth:
  disabled: true                # local only!
servers:
  echo:
    command: host-my-mcp-echo
    allowed_users: ["*"]
    tools:
      allow: ["*"]
      deny: ["admin_*", "crash"]
YAML

host-my-mcp check               # validates config, prints mounts
host-my-mcp                     # serves on 127.0.0.1:8080
```

Point any Streamable HTTP MCP client at `http://127.0.0.1:8080/echo`, e.g.

```sh
npx @modelcontextprotocol/inspector@latest
# Transport: Streamable HTTP, URL: http://127.0.0.1:8080/echo
```

`host-my-mcp-echo` is a bundled stdio server with `echo`, `whoami`, `slow`
(progress notifications), `fail` and `crash` tools. Swap it for your real
servers once the plumbing works.

## Configuration

Full annotated example: [`host-my-mcp.example.yaml`](host-my-mcp.example.yaml).
`${VAR}` / `${VAR:-default}` are substituted from the environment before parsing,
so secrets never need to be committed.

```yaml
listen: { host: 127.0.0.1, port: 8080 }
public_url: https://mcp-ph.zocomputer.io

auth:
  issuer: https://YOUR_TENANT.us.auth0.com/
  email_claim: https://host-my-mcp/email      # optional, see Auth0 step 7

users:
  brendan:
    subjects: ["google-oauth2|1057…"]           # stable; preferred
    emails: ["you@example.com"]                 # convenience

servers:
  omg:                                          # mounted at /omg, resource https://mcp-ph.zocomputer.io/omg
    command: omg
    args: ["mcp", "-C", "/home/zo/notes"]
    allowed_users: [brendan]
    tools:
      allow: ["*"]
      deny: ["docs_delete"]
```

### Server keys

| key | default | meaning |
| --- | --- | --- |
| `path` | `/<name>` | mount path; also the path component of the default resource |
| `command`, `args`, `env`, `cwd` | | how to spawn the stdio server; stdout is MCP, stderr is logged |
| `resource` | `<public_url><path>` | the OAuth resource identifier the token's `aud` must contain |
| `allowed_users` | `[]` (nobody) | names from `users`; `"*"` admits any authenticated identity |
| `scopes` | `[]` | scopes the token must carry for this resource (all required) |
| `scopes_supported` | `scopes` | what to advertise in protected-resource metadata |
| `tools.allow` / `tools.deny` | `[]` / `[]` | tool-name globs; deny wins; empty allow permits nothing |
| `user_tools.<user>` | | per-user override: `allow` replaces the server allow list, `deny` is merged |
| `filter_tool_list` | `true` | hide tools the caller may not invoke from `tools/list` |
| `lifecycle` | `shared` | `shared` (one child for all sessions) or `per_session` |
| `start` | `lazy` | `lazy` (spawn on first use) or `eager` (at startup) |
| `restart` | `5` / `60s` / `60s` | `max_restarts` within `window_secs`, then `cooldown_secs` failed |
| `request_timeout_secs` | `300` | per-request timeout to the backend (reset by progress) |

**Glob syntax** (deterministic, via `globset`): `*` any run of characters, `?`
one character, `[abc]` / `[a-z]` / `[!x]` classes, `{a,b}` alternation.
`/` is not special. Case-sensitive. `"*"` matches every tool.

### Where the identity comes from

The policy key is the token's `sub` claim (for Google-through-Auth0 that looks
like `google-oauth2|1057…`). Emails are a convenience and only work if the
access token carries an email claim (Auth0 needs an Action for that, step 7).

**Finding your `sub`:** either open the user in Auth0 → *User Management →
Users* and copy *user_id*, or just connect once with a token: the gateway logs
an audit line like

```
audit: server=omg stage=authn outcome=deny subject=google-oauth2|1057… user=- detail=subject `google-oauth2|1057…` does not map to a configured user
```

and you paste that subject into `users`.

## Auth0 setup walkthrough

Goal: Auth0 is the authorization server, Google is the identity provider, and
every MCP path is a separate Auth0 **API** whose identifier is the path's URL.
MCP clients discover all of this automatically from the gateway's 401 challenge.

The steps use the dashboard and the [Auth0 CLI](https://github.com/auth0/auth0-cli)
(`brew install auth0/auth0-cli/auth0`, then `auth0 login`). Replace
`YOUR_TENANT.us.auth0.com` and `mcp-ph.zocomputer.io` with your values.

### 1. Tenant toggles (Settings → Advanced → Settings)

Turn on all four:

| toggle | why |
| --- | --- |
| **Resource Parameter Compatibility Profile** | MCP clients send RFC 8707 `resource=https://mcp-ph.zocomputer.io/omg` instead of Auth0's `audience`; with this on, Auth0 uses it to pick the API and set `aud`. Required. |
| **Include Issuer in Authorization Responses** | adds `iss` to the redirect, defends against mix-up attacks. Recommended by Auth0 for MCP. |
| **Client ID Metadata Document Registration** | lets clients that publish a CIMD (an HTTPS URL as `client_id`) use your tenant without pre-registration. Auth0 recommends this over DCR. |
| **Dynamic Client Registration (DCR)** | lets clients that only speak RFC 7591 register themselves. Claude, ChatGPT, Cursor and MCP Inspector all support DCR today; CIMD support is newer and uneven. Enable it until every client you care about does CIMD. |

Equivalent CLI for DCR:

```sh
auth0 api patch "tenants/settings" --data '{"flags":{"enable_dynamic_client_registration":true}}'
```

> DCR is *open*: anyone can register an application in your tenant. Registered
> apps are third-party apps that only get what you grant them in step 3, and
> every user still has to pass Google login and your `allowed_users` list, so
> the exposure is bounded. Auth0's Tenant ACL (Enterprise) can restrict it
> further. Watch `auth0 logs list --filter 'type:sapi AND description:"Dynamic client registration"'`.

### 2. Google as the identity provider

*Authentication → Social → Create Connection → Google / Gmail.* Auth0's
development keys work for testing; for real use create an OAuth client in
Google Cloud Console (type *Web application*, authorized redirect URI
`https://YOUR_TENANT.us.auth0.com/login/callback`) and paste its client ID and
secret into the connection.

Then **promote the connection to domain level** so third-party apps (anything
registered through DCR or CIMD) can use it. *Connection → Settings → Advanced →
Promote Connection to Domain Level*, or:

```sh
auth0 api get connections            # find the google-oauth2 connection id (con_…)
auth0 api patch "connections/con_XXXX" --data '{"is_domain_connection":true}'
```

If you also keep a Username-Password database connection, either promote it
too or (simpler) disable it so Google is the only way in.

### 3. One API per MCP path

For each server in your config, create an API whose **Identifier is exactly the
resource URL** the gateway advertises. By default that is `public_url` + path,
no trailing slash. `host-my-mcp metadata` prints the exact value for each
server.

```sh
for name in omg toggl attn; do
  auth0 api post resource-servers --data "$(cat <<JSON
{
  "name": "mcp ${name}",
  "identifier": "https://mcp-ph.zocomputer.io/${name}",
  "signing_alg": "RS256",
  "token_lifetime": 3600,
  "allow_offline_access": true,
  "skip_consent_for_verifiable_first_party_clients": true
}
JSON
)"
done
```

Dashboard equivalent: *Applications → APIs → Create API*; Identifier
`https://mcp-ph.zocomputer.io/omg`; JSON Web Token Profile *Auth0* or *RFC
9068* (both work); signing RS256. Under *Settings*: **Allow Offline Access**
on (clients get refresh tokens and stop re-prompting), token expiration 3600s
or less.

**Grant third-party apps access.** DCR/CIMD clients are third-party apps and
cannot be granted access one by one, so on *each* API open *Settings →
Default Permissions for Third-Party Applications* (older tenants: *Application
Access Policy*) and set *User-Delegated Access* to **All** (or **Authorized**
with the scopes you define in step 4). Without this, clients get
`access_denied` from Auth0 before they ever reach the gateway.

Why one API per path and not one API with scopes? Because the token's `aud`
is then the path itself, and the gateway refuses a token whose `aud` does not
contain the resource being accessed (RFC 8707). If you prefer a single API,
set `resource:` on every server to that one identifier and use `scopes:` per
server (`omg:use`, `toggl:use`, …) so cross-server reuse is still blocked.

### 4. Scopes (optional)

If a server has `scopes: ["toggl:use"]`, define the permission on that API
(*API → Permissions*), and either enable **RBAC + "Add Permissions in the Access
Token"** and assign it to your user via a role, or include it in the third-party
default grant. The gateway reads both the `scope` claim and Auth0's
`permissions` array claim and advertises the required scopes in the 401
challenge and in `scopes_supported`, so clients request them automatically.

Most personal setups do not need scopes at all: `allowed_users` plus tool globs
already bound access tightly.

### 5. Clients: nothing to pre-register (usually)

With steps 1–3, a client connecting to `https://mcp-ph.zocomputer.io/omg` will:
get a 401 whose `WWW-Authenticate` points at
`/.well-known/oauth-protected-resource/omg` → learn the issuer → fetch
`https://YOUR_TENANT.us.auth0.com/.well-known/openid-configuration` → register
itself (CIMD or DCR) → run Authorization Code + PKCE with `resource=…/omg` →
retry with a bearer token. No client secrets anywhere.

If you want a **pre-registered** client instead (for example MCP Inspector at
`http://localhost:6274/oauth/callback`), create a *Native* application with
that callback URL, grant it the API, and enter its client ID in the client.

### 6. Verify discovery

```sh
# authorization server metadata must advertise PKCE and (if enabled) DCR/CIMD
curl -s https://YOUR_TENANT.us.auth0.com/.well-known/openid-configuration \
  | jq '{issuer, code_challenge_methods_supported, registration_endpoint, client_id_metadata_document_supported}'

# the gateway must answer with the RFC 9728 document
curl -s https://mcp-ph.zocomputer.io/.well-known/oauth-protected-resource/omg | jq
# → {"resource":"https://mcp-ph.zocomputer.io/omg","authorization_servers":["https://YOUR_TENANT.us.auth0.com/"],…}

# and challenge unauthenticated requests
curl -si -X POST https://mcp-ph.zocomputer.io/omg | grep -i www-authenticate
```

### 7. (Optional) Put the email in the access token

Auth0 access tokens carry `sub` but not `email`. If you want `emails:` matching
or readable audit lines, add a Post-Login Action (*Actions → Library → Build
Custom*, trigger *Login / Post Login*) and attach it to the Login flow:

```js
exports.onExecutePostLogin = async (event, api) => {
  if (event.user.email) {
    api.accessToken.setCustomClaim("https://host-my-mcp/email", event.user.email);
  }
};
```

and set `auth.email_claim: https://host-my-mcp/email` in the gateway config.
Custom claims must be namespaced URLs; Auth0 silently drops unnamespaced ones.

### 8. Point the gateway at the tenant and connect

```yaml
auth:
  issuer: https://YOUR_TENANT.us.auth0.com/     # exactly as in openid-configuration, trailing slash included
```

Start the gateway, add `https://mcp-ph.zocomputer.io/omg` as a connector in
Claude / ChatGPT / Cursor, complete the Google login, and watch the audit log.
Your first attempt will be denied with your `sub` in the log line (see
"Finding your sub"); add it to `users`, restart, reconnect.

### Checklist

- [ ] Resource Parameter Compatibility Profile on
- [ ] Include Issuer in Authorization Responses on
- [ ] CIMD registration and/or DCR on
- [ ] Google connection created and promoted to domain level
- [ ] One API per path, identifier = exact resource URL, RS256, offline access
- [ ] Default permissions for third-party applications set on each API
- [ ] (optional) scopes defined and granted
- [ ] (optional) email claim Action
- [ ] `users.<you>.subjects` filled in from the first denied audit line

## Deploying behind Zo

Only the gateway needs a public Zo service. Build on the Zo machine (or copy a
release binary built with `cargo build --release`), then:

1. Put the config at e.g. `~/.config/host-my-mcp/host-my-mcp.yaml` with
   `listen.port: 8080` and `public_url: https://mcp-ph.zocomputer.io`.
   Secrets go in the environment of the service (`${TOGGL_API_TOKEN}` etc.).
2. Run `HOST_MY_MCP_CONFIG=~/.config/host-my-mcp/host-my-mcp.yaml host-my-mcp`
   under your process manager (systemd user unit, pm2, Zo's own service
   runner).
3. Create one Zo public service that forwards `https://mcp-ph.zocomputer.io`
   to `localhost:8080`. The reverse proxy must pass requests for every path
   (`/omg`, `/.well-known/…`, `/healthz`).
4. Decommission the per-server Zo services and their obscure URLs.

The gateway validates the `Host` header (DNS-rebinding protection). It accepts
the `public_url` host, loopback, and `listen.host`. If Zo's proxy rewrites
`Host` to something else, add it to `listen.allowed_hosts`, or set
`["*"]` to disable the check when you trust the proxy.

## How requests are authorized

Every HTTP request to a mount (POST, GET for the SSE stream, DELETE) goes
through the same gate, in order, failing closed:

1. **Bearer token present?** No → `401` with
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/<path>", scope="…"`.
2. **Token valid for this resource?** Signature against the issuer's JWKS,
   `iss`, `exp`/`nbf`, and `aud` must contain this server's `resource`
   (trailing slash and scheme/host case are normalized, nothing else). No →
   `401 invalid_token`. Keys unreachable → `503` (never a silent allow).
3. **Who is it?** `sub` (then email) is resolved to a `users` entry; the server's
   `allowed_users` and `scopes` are checked. No → `403` (`insufficient_scope`
   challenge when a scope is the problem).
4. **Per message:** `tools/call` is checked against the tool globs (deny →
   JSON-RPC error `-32001 forbidden: …`, the backend never sees it);
   `tools/list` is filtered to permitted tools; other methods are allowed for
   anyone who passed step 3.

Each decision produces one `audit` log line with subject, user, server,
method, tool, allow/deny, reason, latency and backend error. Tokens are never
logged; tool arguments only with `logging.log_arguments: true`.

The policy layer is an interface (`policy::Authorizer`) that receives
`{principal, server, method, tool, arguments}`, so argument-level rules or an
external policy engine can replace the static YAML later without touching the
transport code.

## Operations

```sh
host-my-mcp check        # validate config, print mounts and resources
host-my-mcp metadata     # print each RFC 9728 document the gateway will serve
host-my-mcp              # serve
RUST_LOG=info,audit=info,backend=warn host-my-mcp
```

- `GET /healthz` → `ok`
- `GET /status` → JSON with each backend's state (`stopped` / `running` /
  `failed`), pid, uptime, restarts in the current window, last exit reason,
  and live session count.

Backends are spawned lazily (or eagerly with `start: eager`), restarted on
exit within `restart.max_restarts` per `window_secs`, and then marked failed
for `cooldown_secs`, during which requests get a clean "backend unavailable"
error. A crashing backend never takes the gateway or other backends down.
Children's stderr is logged under the `backend` target; stdout is reserved for
MCP framing. On shutdown (SIGINT/SIGTERM) sessions are closed and children
stopped.

## Design notes and limitations

- **Protocol versions.** The gateway negotiates MCP versions up to
  `2025-11-25`. The `2026-07-28` revision removes sessions, which the gateway
  relies on to route notifications per client; support can be added when the
  backends and clients catch up.
- **Shared backends and notifications.** With `lifecycle: shared`, one child
  serves every session. Requests are multiplexed with distinct ids; progress
  notifications are routed back to exactly the session that made the call (the
  gateway rewrites progress tokens both ways); `*/list_changed`,
  `resources/updated` and logging notifications fan out to every session of
  that server. Server-initiated *requests* (sampling, elicitation, roots) are
  not forwarded because a shared child has no session to address; the gateway
  advertises no such client capabilities, so well-behaved servers will not
  send them. Use `lifecycle: per_session` for servers that must not be shared.
- **`tools/list` filtering** is ergonomics, not the security boundary: every
  `tools/call` is independently authorized. Filtering is a pure name match and
  does not rewrite schemas.
- **Resource-level (non-tool) methods** are allowed for any identity admitted
  to the server. Finer rules for `resources/read` or `prompts/get` can be added
  behind the same `Authorizer` interface.
- **Token passthrough is never done.** Backends receive no token; they get
  whatever credentials their own `env` configures.
- **One Auth0 API per path** is the recommended model (tokens bound by
  `aud`). A single API with per-server scopes also works (`resource:` +
  `scopes:`), but then every path shares one audience.

## Development

```sh
cargo test                 # unit tests + end-to-end tests (spawn the echo binary, mint RS256 JWTs)
cargo clippy --all-targets
```

The end-to-end tests cover the unauthenticated bridge, per-session progress
routing with two concurrent clients, crash → restart → budget exhaustion, and
the OAuth surface (challenge header, metadata document, wrong audience,
unknown identity, missing scope, happy path).

## License

MIT
