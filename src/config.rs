//! Configuration loading and validation.
//!
//! The configuration is YAML. Before parsing, `${VAR}` and `${VAR:-default}`
//! references are substituted from the process environment so that secrets
//! and host-specific values never need to be committed.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("environment variable `{0}` referenced in config is not set and has no default")]
    MissingEnv(String),
    #[error("invalid YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    /// Public origin clients use, e.g. `https://mcp.example.com`. No trailing slash.
    pub public_url: Url,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    pub servers: BTreeMap<String, Server>,
    #[serde(default)]
    pub logging: Logging,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Extra `Host` header values to accept (the public host and loopback are
    /// always accepted). Use `["*"]` to disable Host validation entirely.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Browser origins to accept, as `scheme://host`, `scheme://host:port` or
    /// `scheme://host:*` (any port). Doubles as the CORS allowlist: listed
    /// origins get preflight answers and CORS headers, others get neither.
    /// Empty disables Origin validation and emits no CORS headers. `*` and
    /// `null` are rejected (bearer-token API).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8080
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Set to `true` to run without authentication (local development only).
    /// Every request is then treated as the anonymous principal, which must be
    /// granted access via `allowed_users: ["*"]` on a server.
    #[serde(default)]
    pub disabled: bool,
    /// OAuth issuer, e.g. `https://TENANT.us.auth0.com/` (Auth0 issuers end with `/`).
    #[serde(default)]
    pub issuer: Option<Url>,
    /// JWKS URL; defaults to `<issuer>.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_uri: Option<Url>,
    /// Signing algorithms to accept.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// Claim carrying a human-readable email, if the authorization server adds one.
    /// Auth0 access tokens need an Action to add e.g. `https://host-my-mcp/email`.
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    /// Leeway for `exp` / `nbf` validation.
    #[serde(default = "default_leeway")]
    pub leeway_secs: u64,
    /// Minimum interval between JWKS refreshes triggered by unknown key ids.
    #[serde(default = "default_jwks_min_refresh")]
    pub jwks_min_refresh_secs: u64,
    /// Maximum age of cached JWKS before a background refresh is attempted.
    #[serde(default = "default_jwks_max_age")]
    pub jwks_max_age_secs: u64,
    /// Scopes advertised in protected-resource metadata when a server does not
    /// declare its own (`scopes_supported`).
    #[serde(default)]
    pub default_scopes: Vec<String>,
    /// Upstream OpenID Connect identity providers (`google`, …). When this map
    /// is non-empty the gateway is its own OAuth 2.1 authorization server:
    /// MCP clients register, authorize and fetch tokens from the gateway, and
    /// the human login step is delegated to one of these providers.
    /// Mutually exclusive with `issuer`.
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
    /// Directory for the built-in authorization server's state (signing key,
    /// registered clients, refresh tokens, remembered consents). Defaults to
    /// `$XDG_STATE_HOME/host-my-mcp` or `~/.local/state/host-my-mcp`.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Lifetime of access tokens minted by the built-in authorization server.
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_secs: u64,
    /// Lifetime of refresh tokens minted by the built-in authorization server
    /// (rotated on every use; this bounds how long a client can stay signed in
    /// without a new Google login).
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl_secs: u64,
    /// Accept RFC 7591 dynamic client registration (built-in server only).
    /// Every MCP client in common use relies on it; registration is open but
    /// grants nothing by itself, since every login still passes the identity
    /// provider, `users`, and `allowed_users`.
    #[serde(default = "default_true")]
    pub dynamic_registration: bool,
}

/// One upstream OpenID Connect provider used by the built-in authorization
/// server for the human login step.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    /// OIDC issuer, e.g. `https://accounts.google.com`. Discovery is read from
    /// `<issuer>/.well-known/openid-configuration` at startup.
    pub issuer: Url,
    /// OAuth client id registered with the provider for this gateway.
    pub client_id: String,
    /// The matching client secret. Use `${GOOGLE_CLIENT_SECRET}`.
    pub client_secret: String,
    /// Scopes requested from the provider.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// Label shown on the provider picker and consent page.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Refuse identities whose provider reports `email_verified: false`.
    #[serde(default = "default_true")]
    pub require_verified_email: bool,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}
fn default_access_token_ttl() -> u64 {
    3600
}
fn default_refresh_token_ttl() -> u64 {
    30 * 24 * 3600
}

/// How the gateway authenticates requests, derived from `auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// `auth.disabled: true`: everyone is `anonymous`.
    Disabled,
    /// `auth.issuer` names an external authorization server (Auth0, …).
    External,
    /// `auth.providers` is set: the gateway is the authorization server.
    BuiltIn,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into()]
}
fn default_email_claim() -> String {
    "email".into()
}
fn default_leeway() -> u64 {
    30
}
fn default_jwks_min_refresh() -> u64 {
    30
}
fn default_jwks_max_age() -> u64 {
    6 * 3600
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            disabled: false,
            issuer: None,
            jwks_uri: None,
            algorithms: default_algorithms(),
            email_claim: default_email_claim(),
            leeway_secs: default_leeway(),
            jwks_min_refresh_secs: default_jwks_min_refresh(),
            jwks_max_age_secs: default_jwks_max_age(),
            default_scopes: Vec::new(),
            providers: BTreeMap::new(),
            state_dir: None,
            access_token_ttl_secs: default_access_token_ttl(),
            refresh_token_ttl_secs: default_refresh_token_ttl(),
            dynamic_registration: true,
        }
    }
}

impl Auth {
    pub fn mode(&self) -> AuthMode {
        if self.disabled {
            AuthMode::Disabled
        } else if !self.providers.is_empty() {
            AuthMode::BuiltIn
        } else {
            AuthMode::External
        }
    }

    /// Resolved state directory for the built-in authorization server.
    pub fn state_dir(&self) -> PathBuf {
        if let Some(d) = &self.state_dir {
            return d.clone();
        }
        if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(x).join("host-my-mcp");
        }
        match std::env::var_os("HOME") {
            Some(h) => PathBuf::from(h)
                .join(".local")
                .join("state")
                .join("host-my-mcp"),
            None => PathBuf::from(".host-my-mcp-state"),
        }
    }

    pub fn jwks_uri(&self) -> Option<Url> {
        if let Some(u) = &self.jwks_uri {
            return Some(u.clone());
        }
        let issuer = self.issuer.as_ref()?;
        issuer.join(".well-known/jwks.json").ok()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Stable subject identifiers (`sub` claim), e.g. `google-oauth2|1234567890`.
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Email addresses, matched case-insensitively against the configured email claim.
    #[serde(default)]
    pub emails: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// One backend process shared by every authorized session (default).
    #[default]
    Shared,
    /// One backend process per MCP session, killed when the session ends.
    PerSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Start {
    /// Spawn the backend on first use (default).
    #[default]
    Lazy,
    /// Spawn the backend when the gateway starts.
    Eager,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Restart {
    /// Maximum restarts within `window_secs` before the backend is marked failed.
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    #[serde(default = "default_restart_window")]
    pub window_secs: u64,
    /// How long a failed backend stays failed before restarts are attempted again.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_max_restarts() -> u32 {
    5
}
fn default_restart_window() -> u64 {
    60
}
fn default_cooldown() -> u64 {
    60
}

impl Default for Restart {
    fn default() -> Self {
        Self {
            max_restarts: default_max_restarts(),
            window_secs: default_restart_window(),
            cooldown_secs: default_cooldown(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRules {
    /// Globs of tool names that may be called. Empty allows nothing.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Globs of tool names that may never be called. Deny wins over allow.
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// URL path the server is mounted at. Defaults to `/<name>`.
    #[serde(default)]
    pub path: Option<String>,
    /// Program to run. Resolved via `PATH` if not absolute.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// OAuth resource identifier this path is protected as. Defaults to
    /// `<public_url><path>`. Tokens must carry it in `aud`.
    #[serde(default)]
    pub resource: Option<Url>,
    /// Scopes a token must contain to reach this server (all required).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Scopes advertised in protected-resource metadata; defaults to `scopes`
    /// then `auth.default_scopes`.
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub start: Start,
    #[serde(default)]
    pub restart: Restart,
    /// Per-request timeout when talking to the backend.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Names from `users` that may use this server. `"*"` admits any
    /// authenticated principal (or anonymous when auth is disabled).
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// Tool rules applied to everyone allowed on this server.
    #[serde(default)]
    pub tools: ToolRules,
    /// Per-user tool rule overrides. A user's `allow` replaces the server
    /// `allow`; `deny` lists are merged.
    #[serde(default)]
    pub user_tools: BTreeMap<String, ToolRules>,
    /// Filter `tools/list` to tools the caller may invoke (default true).
    #[serde(default = "default_true")]
    pub filter_tool_list: bool,
}

fn default_request_timeout() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    /// `tracing` filter directive, e.g. `info,host_my_mcp=debug`. `RUST_LOG` overrides.
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
    /// Include `tools/call` arguments in audit lines (off by default; may leak secrets).
    #[serde(default)]
    pub log_arguments: bool,
}

fn default_log_level() -> String {
    "info".into()
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
            log_arguments: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let substituted = substitute_env(raw, |k| std::env::var(k).ok())?;
        let mut cfg: Config = serde_yaml_ng::from_str(&substituted)?;
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    fn normalize_and_validate(&mut self) -> Result<(), ConfigError> {
        // public_url: scheme + host, no query/fragment; strip trailing slash.
        if self.public_url.query().is_some() || self.public_url.fragment().is_some() {
            return Err(ConfigError::Invalid(
                "public_url must not contain a query string or fragment".into(),
            ));
        }
        if self.public_url.path() != "/" && !self.public_url.path().is_empty() {
            return Err(ConfigError::Invalid(
                "public_url must be an origin without a path (mount servers via `path`)".into(),
            ));
        }
        if !matches!(self.public_url.scheme(), "http" | "https") {
            return Err(ConfigError::Invalid("public_url must be http(s)".into()));
        }

        if self.auth.mode() == AuthMode::BuiltIn {
            if self.auth.issuer.is_some() || self.auth.jwks_uri.is_some() {
                return Err(ConfigError::Invalid(
                    "auth.providers (built-in authorization server) and auth.issuer / auth.jwks_uri (external authorization server) are mutually exclusive".into(),
                ));
            }
            if self.public_url.scheme() != "https" && !is_loopback_host(&self.public_url) {
                return Err(ConfigError::Invalid(
                    "public_url must use https when the built-in authorization server is enabled (OAuth redirects carry codes); http is only accepted for loopback hosts".into(),
                ));
            }
            for (name, p) in &self.auth.providers {
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(ConfigError::Invalid(format!(
                        "auth.providers key `{name}` must be non-empty and contain only [A-Za-z0-9_-]"
                    )));
                }
                if p.issuer.scheme() != "https" && !is_loopback_host(&p.issuer) {
                    return Err(ConfigError::Invalid(format!(
                        "auth.providers.{name}.issuer must use https"
                    )));
                }
                if p.client_id.trim().is_empty() || p.client_secret.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "auth.providers.{name}: client_id and client_secret are required"
                    )));
                }
                if !p.scopes.iter().any(|s| s == "openid") {
                    return Err(ConfigError::Invalid(format!(
                        "auth.providers.{name}.scopes must include `openid`"
                    )));
                }
            }
            if self.auth.access_token_ttl_secs < 60 || self.auth.refresh_token_ttl_secs < 60 {
                return Err(ConfigError::Invalid(
                    "auth.access_token_ttl_secs and auth.refresh_token_ttl_secs must be at least 60".into(),
                ));
            }
            if self.users.is_empty() {
                return Err(ConfigError::Invalid(
                    "the built-in authorization server needs at least one entry under `users` (emails or subjects) to decide who may sign in".into(),
                ));
            }
        } else if !self.auth.disabled {
            let issuer = self.auth.issuer.as_ref().ok_or_else(|| {
                ConfigError::Invalid("auth.issuer (external authorization server) or auth.providers (built-in authorization server with Google sign-in) is required unless auth.disabled is true".into())
            })?;
            if issuer.scheme() != "https" {
                return Err(ConfigError::Invalid("auth.issuer must use https".into()));
            }
            if self.auth.algorithms.is_empty() {
                return Err(ConfigError::Invalid(
                    "auth.algorithms must not be empty".into(),
                ));
            }
            for alg in &self.auth.algorithms {
                if !matches!(
                    alg.as_str(),
                    "RS256"
                        | "RS384"
                        | "RS512"
                        | "PS256"
                        | "PS384"
                        | "PS512"
                        | "ES256"
                        | "ES384"
                        | "EdDSA"
                ) {
                    return Err(ConfigError::Invalid(format!(
                        "unsupported auth algorithm `{alg}` (asymmetric algorithms only)"
                    )));
                }
            }
        }

        crate::http::cors::OriginAllowlist::parse(&self.listen.allowed_origins)
            .map_err(|e| ConfigError::Invalid(format!("listen.allowed_origins: {e}")))?;

        if self.servers.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one server must be configured".into(),
            ));
        }

        let mut seen_paths = std::collections::BTreeSet::new();
        for (name, server) in self.servers.iter_mut() {
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                || name.is_empty()
            {
                return Err(ConfigError::Invalid(format!(
                    "server name `{name}` must be non-empty and contain only [A-Za-z0-9_-]"
                )));
            }
            let path = server.path.clone().unwrap_or_else(|| format!("/{name}"));
            let path = normalize_path(&path).ok_or_else(|| {
                ConfigError::Invalid(format!("server `{name}`: path `{path}` must start with `/`, must not be `/`, and must not contain `..`, `?`, `#`, or whitespace"))
            })?;
            if path.starts_with("/.well-known")
                || path == "/healthz"
                || path == "/status"
                || path == "/oauth"
                || path.starts_with("/oauth/")
            {
                return Err(ConfigError::Invalid(format!(
                    "server `{name}`: path `{path}` is reserved"
                )));
            }
            if !seen_paths.insert(path.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "server `{name}`: path `{path}` is used by another server"
                )));
            }
            server.path = Some(path.clone());

            if server.resource.is_none() {
                let mut r = self.public_url.clone();
                r.set_path(&path);
                server.resource = Some(r);
            }
            if server.command.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "server `{name}`: command must not be empty"
                )));
            }
            if server.request_timeout_secs == 0 {
                return Err(ConfigError::Invalid(format!(
                    "server `{name}`: request_timeout_secs must be > 0"
                )));
            }
            for u in &server.allowed_users {
                if u != "*" && !self.users.contains_key(u) {
                    return Err(ConfigError::Invalid(format!(
                        "server `{name}`: allowed_users entry `{u}` is not defined under `users`"
                    )));
                }
            }
            for u in server.user_tools.keys() {
                if !self.users.contains_key(u) {
                    return Err(ConfigError::Invalid(format!(
                        "server `{name}`: user_tools entry `{u}` is not defined under `users`"
                    )));
                }
            }
            if server.allowed_users.is_empty() {
                tracing::warn!(server = %name, "no allowed_users configured; nobody can use this server");
            }
            if server.allowed_users.iter().any(|u| u == "*") && !self.auth.disabled {
                tracing::warn!(server = %name, "allowed_users contains \"*\": any authenticated identity with a valid token for this resource may use it");
            }
            // Validate globs early so a typo fails at startup, not at first call.
            for g in server.tools.allow.iter().chain(server.tools.deny.iter()) {
                crate::policy::compile_glob(g).map_err(|e| {
                    ConfigError::Invalid(format!("server `{name}`: bad tool glob `{g}`: {e}"))
                })?;
            }
            for (u, rules) in &server.user_tools {
                for g in rules.allow.iter().chain(rules.deny.iter()) {
                    crate::policy::compile_glob(g).map_err(|e| {
                        ConfigError::Invalid(format!(
                            "server `{name}` user `{u}`: bad tool glob `{g}`: {e}"
                        ))
                    })?;
                }
            }
        }

        for (name, user) in &self.users {
            if user.subjects.is_empty() && user.emails.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "user `{name}` has neither subjects nor emails"
                )));
            }
        }
        Ok(())
    }

    pub fn public_origin(&self) -> String {
        self.public_url.as_str().trim_end_matches('/').to_string()
    }

    /// The authorization server MCP clients are sent to: the gateway itself
    /// in built-in mode, `auth.issuer` for an external one, none when
    /// authentication is disabled.
    pub fn authorization_server(&self) -> Option<String> {
        match self.auth.mode() {
            AuthMode::Disabled => None,
            AuthMode::External => self.auth.issuer.as_ref().map(|u| u.as_str().to_string()),
            AuthMode::BuiltIn => Some(self.public_origin()),
        }
    }

    pub fn request_timeout(server: &Server) -> Duration {
        Duration::from_secs(server.request_timeout_secs)
    }
}

impl Server {
    /// The mount path; always present after validation.
    pub fn path(&self) -> &str {
        self.path.as_deref().expect("path is set during validation")
    }

    /// The OAuth resource identifier; always present after validation.
    pub fn resource(&self) -> &Url {
        self.resource
            .as_ref()
            .expect("resource is set during validation")
    }

    pub fn advertised_scopes<'a>(&'a self, auth: &'a Auth) -> &'a [String] {
        if let Some(s) = &self.scopes_supported {
            return s;
        }
        if !self.scopes.is_empty() {
            return &self.scopes;
        }
        &auth.default_scopes
    }
}

/// `localhost`, `127.0.0.0/8` or `::1`.
pub fn is_loopback_host(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Normalize a mount path: must start with `/`, no trailing slash, no `..`.
fn normalize_path(p: &str) -> Option<String> {
    let p = p.trim();
    if !p.starts_with('/') || p == "/" {
        return None;
    }
    if p.contains("..") || p.contains('?') || p.contains('#') || p.chars().any(char::is_whitespace)
    {
        return None;
    }
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains("//") {
        return None;
    }
    Some(trimmed.to_string())
}

/// Replace `${NAME}` and `${NAME:-default}` with environment values.
pub fn substitute_env(
    input: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, ConfigError> {
    let re =
        regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("static regex");
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for cap in re.captures_iter(input) {
        let m = cap.get(0).unwrap();
        out.push_str(&input[last..m.start()]);
        let name = &cap[1];
        match lookup(name) {
            Some(v) => out.push_str(&v),
            None => match cap.get(2) {
                Some(d) => out.push_str(d.as_str()),
                None => return Err(ConfigError::MissingEnv(name.to_string())),
            },
        }
        last = m.end();
    }
    out.push_str(&input[last..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
public_url: https://mcp.example.com
auth:
  issuer: https://tenant.us.auth0.com/
users:
  brendan:
    subjects: ["google-oauth2|123"]
servers:
  echo:
    command: host-my-mcp-echo
    allowed_users: [brendan]
    tools:
      allow: ["*"]
"#;

    #[test]
    fn minimal_config_defaults() {
        let cfg = Config::parse(MINIMAL).unwrap();
        let s = &cfg.servers["echo"];
        assert_eq!(s.path(), "/echo");
        assert_eq!(s.resource().as_str(), "https://mcp.example.com/echo");
        assert_eq!(
            cfg.auth.jwks_uri().unwrap().as_str(),
            "https://tenant.us.auth0.com/.well-known/jwks.json"
        );
        assert_eq!(cfg.listen.port, 8080);
        assert_eq!(s.lifecycle, Lifecycle::Shared);
        assert!(s.filter_tool_list);
    }

    #[test]
    fn env_substitution() {
        let out = substitute_env("a=${A} b=${B:-dflt} c=${C:-}", |k| match k {
            "A" => Some("1".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(out, "a=1 b=dflt c=");
        assert!(matches!(
            substitute_env("${NOPE}", |_| None),
            Err(ConfigError::MissingEnv(_))
        ));
    }

    #[test]
    fn rejects_unknown_user_and_duplicate_paths() {
        let bad = MINIMAL.replace("allowed_users: [brendan]", "allowed_users: [nobody]");
        assert!(Config::parse(&bad).is_err());

        let dup = format!(
            "{MINIMAL}  echo2:\n    command: x\n    path: /echo\n    allowed_users: [brendan]\n"
        );
        assert!(Config::parse(&dup).is_err());
    }

    #[test]
    fn rejects_public_url_with_path_and_missing_issuer() {
        let bad = MINIMAL.replace("https://mcp.example.com", "https://mcp.example.com/base");
        assert!(Config::parse(&bad).is_err());
        let bad = MINIMAL.replace("  issuer: https://tenant.us.auth0.com/\n", "");
        assert!(Config::parse(&bad).is_err());
        let ok = MINIMAL.replace(
            "  issuer: https://tenant.us.auth0.com/\n",
            "  disabled: true\n",
        );
        assert!(Config::parse(&ok).is_ok());
    }

    #[test]
    fn path_normalization() {
        assert_eq!(normalize_path("/omg/").unwrap(), "/omg");
        assert_eq!(normalize_path("/a/b").unwrap(), "/a/b");
        assert!(normalize_path("/").is_none());
        assert!(normalize_path("omg").is_none());
        assert!(normalize_path("/../x").is_none());
    }

    #[test]
    fn allowed_origins_validated() {
        let ok = MINIMAL.replace(
            "public_url:",
            "listen:\n  allowed_origins: [\"http://localhost:5173\", \"https://app.example.com\", \"http://127.0.0.1:*\"]\npublic_url:",
        );
        assert!(Config::parse(&ok).is_ok());
        for bad in [
            "\"*\"",
            "null",
            "localhost:5173",
            "\"https://app.example.com/path\"",
        ] {
            let yaml = MINIMAL.replace(
                "public_url:",
                &format!("listen:\n  allowed_origins: [{bad}]\npublic_url:"),
            );
            let err = Config::parse(&yaml).unwrap_err().to_string();
            assert!(err.contains("listen.allowed_origins"), "{bad}: {err}");
        }
    }

    #[test]
    fn bad_glob_rejected() {
        let bad = MINIMAL.replace(r#"allow: ["*"]"#, r#"allow: ["[unclosed"]"#);
        assert!(Config::parse(&bad).is_err());
    }
}
