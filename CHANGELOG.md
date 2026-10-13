# Changelog

All notable changes to `host-my-mcp` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may break).

## [0.3.1] - 2026-10-13

### Fixed
- **Consent page could not complete in Chrome.** The consent page's Content
  Security Policy included `form-action 'self'`; Chrome also applies that
  directive to the redirect that follows the form POST, and the post-consent
  redirect goes to the MCP client's callback (`https://chatgpt.com/…`,
  `http://localhost:…`), so the browser stayed on the callback URL and a second
  click on *Allow* got `400 Sign-in expired` because the first one had already
  consumed the login. The directive is gone; the rest of the policy is
  unchanged.
- Pages are served with `Cache-Control: no-store, no-transform` and email
  addresses are wrapped in Cloudflare's `email_off` markers, so a CDN's HTML
  rewriting (email obfuscation, injected analytics scripts) neither mangles the
  identity shown on the consent page nor trips the CSP. README troubleshooting
  row added.

## [0.3.0] - 2026-10-13

### Added
- **Built-in OAuth 2.1 authorization server with Google sign-in.** Setting
  `auth.providers.<name>` (issuer, client_id, client_secret of an OpenID
  Connect provider) makes the gateway its own authorization server: RFC 8414
  metadata at `/.well-known/oauth-authorization-server`, RFC 7591 dynamic
  client registration at `/oauth/register`, Authorization Code with mandatory
  PKCE `S256` and RFC 8707 `resource` at `/oauth/authorize`, upstream OIDC
  login (PKCE + nonce, ID token verified against the provider's JWKS),
  per-client consent page (remembered), single-use codes, rotating refresh
  tokens at `/oauth/token`, EdDSA-signed access tokens whose `aud` is exactly
  the requested mount(s), JWKS at `/oauth/jwks`. Subjects are
  `<provider>|<sub>`; the verified `email` is in the token, so
  `users.<name>.emails` needs no extra configuration. State (signing key,
  clients, hashed refresh tokens, consents) persists under `auth.state_dir`
  (default `~/.local/state/host-my-mcp`). Mounts validate the tokens through
  the unchanged resource-server path. README: "Google sign-in setup" (Google
  Cloud Console walkthrough and troubleshooting), "How the built-in
  authorization server works", "Other identity providers".
- `host-my-mcp check` prints the auth mode and, in built-in mode, the exact
  redirect URI to register at the provider. `/status` reports `auth: builtin`.
- Config: `auth.providers`, `auth.state_dir`, `auth.access_token_ttl_secs`,
  `auth.refresh_token_ttl_secs`, `auth.dynamic_registration`. `/oauth/*` is a
  reserved mount path. `auth.providers` and `auth.issuer` are mutually
  exclusive; built-in mode requires `https` `public_url` (loopback excepted)
  and at least one `users` entry.

### Changed
- README leads with the Google setup; the Auth0 walkthrough moved to a link to
  the 0.2.0 README under "External authorization server instead". External
  issuers keep working unchanged.
- Crate description and keywords no longer mention Auth0.

## [0.2.0] - 2026-10-09

First published release.

### Added
- **CORS for browser MCP clients**, keyed on `listen.allowed_origins`. For each
  listed origin the gateway answers `OPTIONS` preflights on every mount and on
  `/.well-known/oauth-protected-resource/<path>` with `204` (no token required)
  and adds `Access-Control-Allow-Origin`, `Vary: Origin` and
  `Access-Control-Expose-Headers: WWW-Authenticate, Mcp-Session-Id,
  Mcp-Protocol-Version` to every response, including the `401` challenge, so a
  browser can read the challenge, run discovery/DCR/PKCE against the
  authorization server and keep its MCP session. The origin grammar is rmcp's
  (`scheme://host`, `scheme://host:port`, `scheme://host:*`), so Origin
  validation and CORS can never disagree. An empty list (the default) installs
  no CORS layer; `"*"` and `"null"` are rejected at startup because the gateway
  is a bearer-token API. Note: with a non-empty list rmcp also rejects (403)
  browser requests whose `Origin` is not listed; clients that send no `Origin`
  (CLIs, SDK clients) are unaffected. README: "Listen keys" and "Browser
  clients".

### Changed
- The whole tree is formatted with `rustfmt`; `cargo fmt --check` is green.

## [0.1.0] - 2026-10-01

Initial commit, unpublished: one public Streamable HTTP MCP gateway that
authenticates with OAuth (Auth0), authorizes per server and per tool, and
routes paths to local stdio MCP servers.
