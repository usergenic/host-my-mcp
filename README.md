# host-my-mcp

One public, OAuth-protected **Streamable HTTP** MCP gateway in front of many local **stdio** MCP servers. Sign in with your Google account; no Auth0, no hosted identity service.

```text
MCP clients (Claude, ChatGPT, Cursor, MCP Inspector, …)
        │  https://mcp.example.com/<server>
        ▼
┌──────────────────────────────────────────────────────┐
│ host-my-mcp                                          │
│  • OAuth 2.1 authorization server (built in)         │──► Google sign-in
│    DCR · PKCE · consent · resource-bound JWTs        │    (or any OIDC provider)
│  • OAuth 2.1 resource server (validates its tokens)  │
│  • per-server / per-tool authorization               │
│  • Streamable HTTP ⇄ stdio bridge                    │
│  • child-process supervision + audit log             │
└──────┬──────────────┬──────────────┬─────────────────┘
       │ /omg         │ /toggl       │ /attn
       ▼              ▼              ▼
   omg mcp …      toggl-mcp       attn-mcp        (local stdio processes)
```

Each configured server is mounted on its own path **and** is its own OAuth
resource, so a token minted for `/omg` is useless at `/toggl`. The gateway is
the authorization server MCP clients talk to: they register themselves, run
Authorization Code + PKCE against it, and receive gateway-signed tokens. The
only thing it delegates is the human login, to Google (or another OpenID
Connect provider) through one OAuth client you create in Google Cloud Console.
An external authorization server (Auth0 and friends) is still supported, see
[External authorization server](#external-authorization-server-instead).

Written in Rust on top of the official [`rmcp`](https://crates.io/crates/rmcp)
SDK (both the Streamable HTTP server side and the stdio client side), `axum`,
and `jsonwebtoken`. Single static binary; no runtime dependencies, no database.

## Contents

- [Quick start (no auth, local)](#quick-start-no-auth-local)
- [Google sign-in setup](#google-sign-in-setup)
- [Configuration](#configuration)
- [How the built-in authorization server works](#how-the-built-in-authorization-server-works)
- [Other identity providers](#other-identity-providers)
- [External authorization server instead](#external-authorization-server-instead)
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

## Google sign-in setup

Goal: you connect an MCP client to `https://mcp.example.com/omg`, a
browser window opens, you pick your Google account, you click **Allow** once,
and the client is connected. Google never sees the MCP client; it only sees
the gateway, which is one ordinary "Web application" OAuth client in your
Google Cloud project. The whole setup is about ten minutes and is free.

You need: a Google account, the public HTTPS URL the gateway will have
(`public_url`, e.g. `https://mcp.example.com`), and a shell on the
machine that runs the gateway.

### 1. Create (or pick) a Google Cloud project

1. Open <https://console.cloud.google.com/> and sign in.
2. In the project picker at the top, **New project**. Name it `host-my-mcp`
   (any name works; it is never shown to you later). No organization is
   needed. **Create**, then make sure the new project is selected.

### 2. Configure the OAuth consent screen ("Google Auth Platform")

1. In the left menu (or the search box) open **Google Auth Platform**
   (older consoles call it *APIs & Services → OAuth consent screen*).
2. Click **Get started** and fill in:
   - **App name**: `host-my-mcp` (this is the name Google shows on the
     sign-in screen).
   - **User support email**: your address.
   - **Audience**: choose **External** unless this Google account belongs to a
     Google Workspace organization and you want to restrict sign-in to that
     organization, in which case choose **Internal**.
   - **Contact information**: your address again.
   - Accept the policy, **Create**.
3. Open **Audience** in the left menu. With *External* the app starts in
   **Testing** mode. Leave it there and add yourself under **Test users →
   Add users**. Testing mode means only listed Google accounts can get past
   the Google sign-in screen, which is exactly what a personal gateway wants
   (the gateway's own `users` list is the second lock). The "7-day token
   expiry" warning Google shows for Testing mode does not apply: the gateway
   only uses Google at the moment you sign in and never stores Google tokens.
4. You do not need to add anything under **Data Access** (scopes): the
   gateway only asks for `openid`, `email` and `profile`, which are
   non-sensitive and always available.
5. **Branding** (logo, home page) is optional.

### 3. Create the OAuth client

1. Open **Clients** in the left menu (older consoles: *APIs & Services →
   Credentials → Create credentials → OAuth client ID*).
2. **Create client**:
   - **Application type**: **Web application**.
   - **Name**: `host-my-mcp gateway`.
   - **Authorized JavaScript origins**: leave empty.
   - **Authorized redirect URIs**: **Add URI** and enter exactly

     ```text
     https://mcp.example.com/oauth/callback
     ```

     i.e. your `public_url` followed by `/oauth/callback`, `https`, no
     trailing slash. `host-my-mcp check` prints the exact value for your
     config. Google compares this string byte for byte; the most common
     setup error is a typo here (see troubleshooting).
3. **Create**. Copy the **Client ID** (looks like
   `1234567890-abc…xyz.apps.googleusercontent.com`) and the **Client secret**
   (`GOCSPX-…`). The secret is shown here and in the client's detail page;
   you can also **Download JSON**.

### 4. Put the credentials in the gateway config

Give the two values to the gateway through the environment so they never
land in a file you might commit:

```sh
export GOOGLE_CLIENT_ID='1234567890-abc…xyz.apps.googleusercontent.com'
export GOOGLE_CLIENT_SECRET='GOCSPX-…'
```

```yaml
public_url: https://mcp.example.com

auth:
  providers:
    google:
      issuer: https://accounts.google.com
      client_id: ${GOOGLE_CLIENT_ID}
      client_secret: ${GOOGLE_CLIENT_SECRET}

users:
  brendan:
    emails: ["you@gmail.com"]          # the Google account(s) allowed in

servers:
  omg:
    command: omg
    args: ["mcp", "-C", "/home/zo/notes"]
    allowed_users: [brendan]
    tools:
      allow: ["*"]
```

`users.<name>.emails` is matched against the email Google verifies, so this is
all the identity configuration you need. (If you prefer the stable Google
account id, use `subjects: ["google|1057…"]`; the id is shown on the "This
account is not allowed" page and in the audit log the first time an unknown
account signs in.)

### 5. Start and verify

```sh
host-my-mcp check      # prints: auth: built-in authorization server at https://… (providers: google; state_dir …)
                       #         Google Cloud Console → Authorized redirect URI: https://…/oauth/callback
host-my-mcp
```

On first start the gateway creates `state_dir` (default
`~/.local/state/host-my-mcp`), generates its token-signing key, and reads
Google's discovery document; a wrong `issuer` or an unreachable network fails
here, loudly. Then, from any machine:

```sh
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | jq
# → issuer, authorization_endpoint, token_endpoint, registration_endpoint, jwks_uri, …
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/omg | jq .authorization_servers
# → ["https://mcp.example.com"]
curl -si -X POST https://mcp.example.com/omg | grep -i www-authenticate
# → Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/omg"
```

### 6. Connect a client

Add `https://mcp.example.com/omg` as a connector / remote MCP server in
Claude, ChatGPT, Cursor, or run MCP Inspector against it. The client
registers itself with the gateway, opens the browser, Google asks you to pick
an account, the gateway asks once whether to allow *that client* to use *that
server* as you, and you are in. Nothing to pre-register per client, no client
secrets to paste anywhere.

The first login from a Google account that is not under `users` ends on a
page that shows the account's subject and email so you can add it; the audit
log gets the same line:

```text
audit: server=oauth stage=authn outcome=deny subject=google|1057… user=- detail=identity does not map to a configured user (email you@gmail.com)
```

### Troubleshooting Google

| Google says | Fix |
| --- | --- |
| **Error 400: redirect_uri_mismatch** | The redirect URI in Cloud Console is not byte-identical to `<public_url>/oauth/callback`. Check scheme, host, port, path and trailing slash. Changes take effect within a minute. |
| **Error 403: access_denied** / *"host-my-mcp has not completed the Google verification process"* | Audience is *External* in Testing mode and this Google account is not a test user. Add it under **Audience → Test users**. |
| **Error 403: org_internal** | Audience is *Internal* and the account is outside the Workspace organization. Use *External*, or sign in with an organization account. |
| **Error 401: invalid_client** / *"The OAuth client was not found"* | Client ID or secret is wrong or belongs to another project. Re-copy both; make sure the env vars are set in the gateway's environment, not just your shell. |
| **"This app isn't verified"** interstitial | Only appears if you publish the app to production with sensitive scopes. The gateway uses none; stay in Testing mode or publish without extra scopes. |
| Gateway page **"Sign-in expired"** | More than ten minutes passed between opening the client and finishing login, or the gateway restarted mid-flow. Reconnect from the client. |
| Gateway page **"This account is not allowed"** | Working as intended: add the shown email or subject to `users`, restart, reconnect. |

## Configuration

Full annotated example: [`host-my-mcp.example.yaml`](host-my-mcp.example.yaml).
`${VAR}` / `${VAR:-default}` are substituted from the environment before parsing,
so secrets never need to be committed.

```yaml
listen: { host: 127.0.0.1, port: 8080 }
public_url: https://mcp.example.com

auth:
  providers:
    google:
      issuer: https://accounts.google.com
      client_id: ${GOOGLE_CLIENT_ID}
      client_secret: ${GOOGLE_CLIENT_SECRET}

users:
  brendan:
    emails: ["you@gmail.com"]                   # verified by the provider
    subjects: ["google|1057…"]                  # optional, stable account id

servers:
  omg:                                          # mounted at /omg, resource https://mcp.example.com/omg
    command: omg
    args: ["mcp", "-C", "/home/zo/notes"]
    allowed_users: [brendan]
    tools:
      allow: ["*"]
      deny: ["docs_delete"]
```

### Auth keys

| key | default | meaning |
| --- | --- | --- |
| `providers.<name>.issuer` | | OpenID Connect issuer of an identity provider; `https://accounts.google.com` for Google. Setting any provider turns on the built-in authorization server |
| `providers.<name>.client_id`, `client_secret` | | the OAuth client you created at the provider for this gateway |
| `providers.<name>.scopes` | `[openid, email, profile]` | scopes requested from the provider; must include `openid` |
| `providers.<name>.display_name` | capitalized `<name>` | label on the provider picker when several providers are configured |
| `providers.<name>.require_verified_email` | `true` | refuse identities whose provider reports `email_verified: false` |
| `state_dir` | `$XDG_STATE_HOME/host-my-mcp` or `~/.local/state/host-my-mcp` | signing key, registered clients, refresh tokens, consents (files are `0600`) |
| `access_token_ttl_secs` | `3600` | lifetime of access tokens |
| `refresh_token_ttl_secs` | `2592000` (30 days) | how long a client stays signed in without a new Google login; refresh tokens rotate on every use |
| `dynamic_registration` | `true` | serve RFC 7591 registration; every current MCP client needs it |
| `disabled` | `false` | run without authentication (local only); every caller is `anonymous` |
| `issuer`, `jwks_uri`, `algorithms`, `email_claim`, `leeway_secs`, `jwks_*` | | external authorization server mode, see [below](#external-authorization-server-instead); `issuer` and `providers` are mutually exclusive |
| `default_scopes` | `[]` | scopes advertised for servers that declare none |

### Listen keys

| key | default | meaning |
| --- | --- | --- |
| `host`, `port` | `127.0.0.1`, `8080` | bind address |
| `allowed_hosts` | `[]` | extra `Host` header values to accept (the `public_url` host, loopback and `host` are always accepted); `["*"]` disables the check |
| `allowed_origins` | `[]` | browser origins, `scheme://host`, `scheme://host:port` or `scheme://host:*` (any port). Doubles as the **CORS allowlist**: listed origins get preflight answers and CORS headers, unlisted origins get neither and are rejected with 403. Empty = no Origin validation **and no CORS headers**. `"*"` and `"null"` are rejected at startup |

### Browser clients

The gateway is a bearer-token API, so it never answers `Access-Control-Allow-Origin: *`.
To let a web app (for example a Vite dev server on `http://localhost:5173`, or
your deployed app) connect with the MCP SDK's browser client and OAuth, list its
origin:

```yaml
listen:
  allowed_origins: ["http://localhost:5173", "https://app.example.com"]
```

For each listed origin the gateway answers `OPTIONS` preflights on every mount,
on the well-known documents and on the OAuth endpoints with `204` and
`Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS`,
`Access-Control-Allow-Headers: Authorization, Content-Type, Accept,
Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID`, `Access-Control-Max-Age: 600`,
without requiring a token (browsers never send `Authorization` on a preflight).
Actual responses, including the `401` challenge, the metadata documents and
the token endpoint, carry `Access-Control-Allow-Origin: <origin>`,
`Vary: Origin` and `Access-Control-Expose-Headers: WWW-Authenticate,
Mcp-Session-Id, Mcp-Protocol-Version`, so the browser can read the challenge,
run discovery, registration and PKCE, and keep the MCP session id. Origins
not on the list receive no CORS headers at all. Native and CLI clients send
no `Origin` and are unaffected. Use `http://localhost:*` to accept any port on
localhost during development.

### Server keys

| key | default | meaning |
| --- | --- | --- |
| `path` | `/<name>` | mount path; also the path component of the default resource. `/oauth/*`, `/.well-known/*`, `/healthz`, `/status` are reserved |
| `command`, `args`, `env`, `cwd` | | how to spawn the stdio server; stdout is MCP, stderr is logged |
| `resource` | `<public_url><path>` | the OAuth resource identifier the token's `aud` must contain |
| `allowed_users` | `[]` (nobody) | names from `users`; `"*"` admits any authenticated identity |
| `scopes` | `[]` | scopes the token must carry for this resource (all required). The built-in authorization server grants a server's advertised scopes to every user it admits |
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

The policy key is the token's `sub` claim. Tokens minted by the built-in
authorization server use `<provider>|<provider's sub>`, e.g.
`google|1057…`, and carry the provider-verified `email`, so either
`users.<name>.subjects` or `users.<name>.emails` works. Subjects are stable
even if the account's email changes; emails are easier to type.

## How the built-in authorization server works

The gateway implements the authorization-server half of the
[MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
itself, in the "resource server and authorization server are the same
service, login delegated to a third party" shape the spec describes.

| endpoint | purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` (also `/.well-known/openid-configuration`) | RFC 8414 metadata: endpoints below, `code_challenge_methods_supported: [S256]`, `scopes_supported`, `authorization_response_iss_parameter_supported` |
| `POST /oauth/register` | RFC 7591 dynamic client registration. Accepts `redirect_uris` (https, `http://localhost` / `127.0.0.1` on any port, or a private-use scheme such as `cursor://`), `token_endpoint_auth_method` `none` / `client_secret_basic` / `client_secret_post`, `client_name`, … Returns `client_id` (and a secret for confidential clients) |
| `GET /oauth/authorize` | Authorization Code with mandatory PKCE `S256` and an RFC 8707 `resource` naming one of the mounts (with a single mount configured it may be omitted). Redirects the browser to the identity provider |
| `GET /oauth/callback` | Returns from the provider, verifies the ID token (signature via the provider's JWKS, `iss`, `aud`, `nonce`, expiry, PKCE), resolves the identity against `users`, checks `allowed_users` and `scopes` for the requested mounts, then shows the consent page |
| `POST /oauth/consent` | **Allow** issues a single-use, five-minute authorization code and redirects to the client's registered `redirect_uri` with `code`, `state` and `iss`. The decision is remembered per (account, client), so later logins skip the page |
| `POST /oauth/token` | `authorization_code` (verifies client, code, `redirect_uri`, PKCE, `resource`) and `refresh_token` (rotating; the old token is dead the moment the new one is issued; a token replayed by another client revokes the whole family). Returns `access_token`, `refresh_token`, `expires_in`, `scope` |
| `GET /oauth/jwks` | the gateway's public signing key |

**Tokens.** Access tokens are EdDSA (Ed25519) JWTs, `typ: at+jwt`, with
`iss` = `public_url`, `sub` = `google|…`, `aud` = exactly the resources
requested, `email`, `name`, `client_id`, `scope`, `jti`, one hour by default.
The mounts validate them with the same code path used for an external
issuer, so the audience binding, scope checks and `users` resolution are
identical in both modes. Refresh tokens are opaque and stored hashed.

**Consent.** The MCP spec requires a proxy that fronts dynamically
registered clients with one static upstream client id to obtain the user's
consent per client (otherwise a malicious client could ride a silent Google
re-login). The gateway shows one page naming the client, its redirect URI,
the servers it asked for and the account you signed in with; approve once per
client. Consents, clients and refresh tokens live in `state_dir`, so restarts
are invisible to clients; wipe the directory to force everyone to register
and log in again.

**What Google sees.** One OAuth client, one redirect URI, logins with
`openid email profile`. No Google refresh tokens are requested or stored, no
Google API is called after login, and no Google token ever reaches an MCP
client or a backend.

## Other identity providers

Any OpenID Connect provider with a discovery document works the same way; the
subject becomes `<name>|<sub>` and the email is taken from the ID token:

```yaml
auth:
  providers:
    google:
      issuer: https://accounts.google.com
      client_id: ${GOOGLE_CLIENT_ID}
      client_secret: ${GOOGLE_CLIENT_SECRET}
    microsoft:
      issuer: https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0
      client_id: ${AZURE_CLIENT_ID}
      client_secret: ${AZURE_CLIENT_SECRET}
      display_name: Microsoft 365
```

With more than one provider the authorize endpoint shows a picker page first.
Register `<public_url>/oauth/callback` as the redirect URI at each provider.
Providers that are OAuth 2.0 but not OpenID Connect (GitHub, for example) are
not supported yet.

## External authorization server instead

If you already run an authorization server that supports dynamic client
registration and RFC 8707 resource indicators (Auth0, Keycloak, Pomerium,
…), point the gateway at it instead of configuring providers:

```yaml
auth:
  issuer: https://YOUR_TENANT.us.auth0.com/     # exactly as in its openid-configuration
  # jwks_uri: defaults to <issuer>.well-known/jwks.json
  # algorithms: [RS256]
  # email_claim: https://host-my-mcp/email      # if the server adds an email claim
```

The gateway is then a pure resource server: it validates the issuer's tokens
(signature via JWKS, `iss`, `exp`/`nbf`, `aud` must contain the mount's
`resource`) and the issuer must be configured with one API/resource per mount
whose identifier is the resource URL. The Auth0-specific provisioning
walkthrough (tenant toggles, Google social connection, one API per path,
third-party default permissions, email claim Action) is in the
[0.2.0 README](https://github.com/usergenic/host-my-mcp/blob/v0.2.0/README.md#auth0-setup-walkthrough).

## Deploying behind Zo

Only the gateway needs a public Zo service. Build on the Zo machine (or copy a
release binary built with `cargo build --release`), then:

1. Put the config at e.g. `~/.config/host-my-mcp/host-my-mcp.yaml` with
   `listen.port: 8080` and `public_url: https://mcp.example.com`.
   Secrets go in the environment of the service (`${GOOGLE_CLIENT_SECRET}`,
   `${TOGGL_API_TOKEN}` etc.). `state_dir` must be writable and persistent.
2. Run `HOST_MY_MCP_CONFIG=~/.config/host-my-mcp/host-my-mcp.yaml host-my-mcp`
   under your process manager (systemd user unit, pm2, Zo's own service
   runner).
3. Create one Zo public service that forwards `https://mcp.example.com`
   to `localhost:8080`. The reverse proxy must pass requests for every path
   (`/omg`, `/oauth/…`, `/.well-known/…`, `/healthz`) and must not rewrite
   redirects: the OAuth flow bounces the browser between Google, the gateway
   and the MCP client using `public_url`.
4. Decommission the per-server Zo services and their obscure URLs.

The gateway validates the `Host` header (DNS-rebinding protection). It accepts
the `public_url` host, loopback, and `listen.host`. If Zo's proxy rewrites
`Host` to something else, add it to `listen.allowed_hosts`, or set
`["*"]` to disable the check when you trust the proxy. Browser apps need their
origins in `listen.allowed_origins` (see [Browser clients](#browser-clients));
the proxy must forward `OPTIONS` requests unchanged.

## How requests are authorized

Every HTTP request to a mount (POST, GET for the SSE stream, DELETE) goes
through the same gate, in order, failing closed (CORS preflights from a listed
origin are answered before the gate, carry nothing but CORS headers, and never
reach a backend):

1. **Bearer token present?** No → `401` with
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/<path>", scope="…"`.
2. **Token valid for this resource?** Signature against the issuer's keys
   (the gateway's own key in built-in mode), `iss`, `exp`/`nbf`, and `aud`
   must contain this server's `resource` (trailing slash and scheme/host case
   are normalized, nothing else). No → `401 invalid_token`. External keys
   unreachable → `503` (never a silent allow).
3. **Who is it?** `sub` (then email) is resolved to a `users` entry; the server's
   `allowed_users` and `scopes` are checked. No → `403` (`insufficient_scope`
   challenge when a scope is the problem).
4. **Per message:** `tools/call` is checked against the tool globs (deny →
   JSON-RPC error `-32001 forbidden: …`, the backend never sees it);
   `tools/list` is filtered to permitted tools; other methods are allowed for
   anyone who passed step 3.

Each decision produces one `audit` log line with subject, user, server,
method, tool, allow/deny, reason, latency and backend error. The built-in
authorization server logs `stage=authn` lines for registrations, logins,
consents, token issuance and every denial under `server=oauth`. Tokens are
never logged; tool arguments only with `logging.log_arguments: true`.

The policy layer is an interface (`policy::Authorizer`) that receives
`{principal, server, method, tool, arguments}`, so argument-level rules or an
external policy engine can replace the static YAML later without touching the
transport code.

## Operations

```sh
host-my-mcp check        # validate config, print mounts, resources and the Google redirect URI
host-my-mcp metadata     # print each RFC 9728 document the gateway will serve
host-my-mcp              # serve
RUST_LOG=info,audit=info,backend=warn host-my-mcp
```

- `GET /healthz` → `ok`
- `GET /status` → JSON with `auth` (`builtin` / `oauth` / `disabled`) and
  each backend's state (`stopped` / `running` / `failed`), pid, uptime,
  restarts in the current window, last exit reason, and live session count.
- `state_dir/signing-key.pkcs8`: delete to rotate the signing key (every
  issued access token becomes invalid; clients refresh transparently).
- `state_dir/oauth-state.json`: registered clients, hashed refresh tokens,
  consents. Delete a client entry to force it to re-register; delete the file
  to log everyone out.

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
- **Open registration.** Anyone who can reach the gateway can register a
  client; that is how MCP clients work. A registration grants nothing: the
  human still has to pass Google, be listed under `users`, be in the mount's
  `allowed_users`, and approve that client on the consent page. Registrations
  are capped (least recently used evicted) so the state file cannot grow
  unbounded. Client ID Metadata Documents (URL client ids) are not supported
  yet; clients fall back to registration.
- **Startup needs the provider.** Provider discovery runs at startup and a
  failure is fatal, so a broken `issuer` is caught immediately. A transient
  network outage at boot therefore delays startup until your process manager
  retries.
- **Refresh tokens are always issued** by the built-in server, whether or not
  the client asked for `offline_access`, so clients stay connected for
  `refresh_token_ttl_secs` without re-prompting (the hourly re-login seen with
  some external issuers came from clients not requesting that scope).
- **Login state is in memory.** Pending logins and authorization codes live
  for ten and five minutes respectively and do not survive a restart; clients
  simply start over. Clients, refresh tokens and consents are persisted.

## Development

```sh
cargo test                 # unit tests + end-to-end tests (spawn the echo binary, run a fake OpenID provider)
cargo clippy --all-targets
```

The end-to-end tests cover the unauthenticated bridge, per-session progress
routing with two concurrent clients, crash → restart → budget exhaustion, the
resource-server surface against an external issuer (challenge header, metadata
document, wrong audience, unknown identity, missing scope, happy path), CORS
for browser clients, and the built-in authorization server against a fake
Google-shaped provider (discovery, registration, PKCE, upstream login with
nonce and PKCE, consent and remembered consent, code redemption, audience
binding at the mounts, refresh rotation and replay, scope grants, unknown
identities, forbidden servers, invalid resources, confidential clients, state
persistence across restarts).

## License

MIT
