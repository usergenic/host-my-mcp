# Changelog

All notable changes to `host-my-mcp` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may break).

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
