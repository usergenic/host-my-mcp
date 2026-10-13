//! The built-in OAuth 2.1 authorization server.
//!
//! Enabled when `auth.providers` is set. MCP clients discover it through the
//! RFC 9728 document each mount serves (`authorization_servers` is the
//! gateway's own origin), register with RFC 7591 dynamic client registration,
//! run Authorization Code + PKCE against `/oauth/authorize` and `/oauth/token`
//! with an RFC 8707 `resource`, and receive gateway-signed JWTs whose `aud`
//! is exactly that resource. The human login step is delegated to an upstream
//! OpenID Connect provider ([`upstream`]); the gateway asks for consent once
//! per (identity, client) because it fronts dynamically registered clients
//! with a single static upstream client id (MCP spec, "confused deputy").
//!
//! The rest of the gateway does not know this module exists: the resource
//! server side validates the tokens through the same [`TokenValidator`]
//! it uses for an external issuer, fed by the in-process signing key.

pub mod keys;
pub mod store;
pub mod upstream;
pub mod util;

mod endpoints;
mod html;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    Router,
    routing::{get, post},
};
use serde_json::{Value, json};
use url::Url;

use crate::{auth::token::audience_matches, config::Config, policy::Authorizer};
use keys::Signer;
use store::{Identity, Store};
use upstream::UpstreamProvider;

pub const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OIDC_METADATA_PATH: &str = "/.well-known/openid-configuration";
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const TOKEN_PATH: &str = "/oauth/token";
pub const REGISTER_PATH: &str = "/oauth/register";
pub const JWKS_PATH: &str = "/oauth/jwks";
pub const CALLBACK_PATH: &str = "/oauth/callback";
pub const CONSENT_PATH: &str = "/oauth/consent";

/// Scopes every client may ask for regardless of server configuration.
const BASE_SCOPES: &[&str] = &["openid", "email", "profile", "offline_access"];

/// One protected MCP mount as the authorization server sees it.
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub server: String,
    /// Canonical form, no trailing slash: what goes into `aud`.
    pub resource: String,
    pub url: Url,
    pub scopes: Vec<String>,
}

/// What a token is issued for.
#[derive(Debug, Clone)]
pub struct Grant<'a> {
    pub client_id: &'a str,
    pub identity: &'a Identity,
    pub user: &'a str,
    pub scopes: &'a [String],
    pub resources: &'a [String],
}

pub struct AuthorizationServer {
    /// `public_url` without trailing slash; the `iss` of every token.
    pub issuer: String,
    signer: Arc<Signer>,
    store: Store,
    providers: BTreeMap<String, Arc<UpstreamProvider>>,
    resources: Vec<ResourceInfo>,
    known_scopes: BTreeSet<String>,
    policy: Arc<dyn Authorizer>,
    access_ttl: u64,
    refresh_ttl: u64,
    dynamic_registration: bool,
}

impl AuthorizationServer {
    /// Load keys and state, discover every provider. Fails fast on a bad
    /// provider so a typo surfaces at startup rather than at first login.
    pub async fn build(cfg: &Config, policy: Arc<dyn Authorizer>) -> anyhow::Result<Arc<Self>> {
        let dir = cfg.auth.state_dir();
        let signer = Signer::load_or_create(&dir)?;
        let store = Store::open(&dir)?;
        let (clients, refresh, consents) = store.counts();
        tracing::info!(state_dir = %dir.display(), clients, refresh_tokens = refresh, consents, "authorization server state loaded");

        let mut providers = BTreeMap::new();
        for (name, p) in &cfg.auth.providers {
            providers.insert(name.clone(), UpstreamProvider::discover(name, p).await?);
        }
        Ok(Arc::new(Self::assemble(
            cfg, policy, signer, store, providers,
        )))
    }

    fn assemble(
        cfg: &Config,
        policy: Arc<dyn Authorizer>,
        signer: Arc<Signer>,
        store: Store,
        providers: BTreeMap<String, Arc<UpstreamProvider>>,
    ) -> Self {
        let mut known_scopes: BTreeSet<String> =
            BASE_SCOPES.iter().map(|s| s.to_string()).collect();
        known_scopes.extend(cfg.auth.default_scopes.iter().cloned());
        let resources = cfg
            .servers
            .iter()
            .map(|(name, s)| {
                let scopes = s.advertised_scopes(&cfg.auth).to_vec();
                known_scopes.extend(scopes.iter().cloned());
                known_scopes.extend(s.scopes.iter().cloned());
                ResourceInfo {
                    server: name.clone(),
                    resource: s.resource().as_str().trim_end_matches('/').to_string(),
                    url: s.resource().clone(),
                    scopes,
                }
            })
            .collect();
        Self {
            issuer: cfg.public_origin(),
            signer,
            store,
            providers,
            resources,
            known_scopes,
            policy,
            access_ttl: cfg.auth.access_token_ttl_secs,
            refresh_ttl: cfg.auth.refresh_token_ttl_secs,
            dynamic_registration: cfg.auth.dynamic_registration,
        }
    }

    /// Validates the tokens this server mints (in-process, no HTTP).
    pub fn key_source(&self) -> Arc<dyn crate::auth::jwks::KeySource> {
        self.signer.clone()
    }

    pub fn algorithm(&self) -> jsonwebtoken::Algorithm {
        self.signer.algorithm()
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(METADATA_PATH, get(endpoints::metadata))
            .route(OIDC_METADATA_PATH, get(endpoints::metadata))
            .route(JWKS_PATH, get(endpoints::jwks))
            .route(REGISTER_PATH, post(endpoints::register))
            .route(AUTHORIZE_PATH, get(endpoints::authorize))
            .route(CALLBACK_PATH, get(endpoints::callback))
            .route(CONSENT_PATH, post(endpoints::consent))
            .route(TOKEN_PATH, post(endpoints::token))
            .with_state(self.clone())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }

    pub fn callback_url(&self) -> String {
        self.url(CALLBACK_PATH)
    }

    /// RFC 8414 document (also served as `openid-configuration` because some
    /// clients only try that path).
    pub fn metadata(&self) -> Value {
        let mut md = json!({
            "issuer": self.issuer,
            "authorization_endpoint": self.url(AUTHORIZE_PATH),
            "token_endpoint": self.url(TOKEN_PATH),
            "jwks_uri": self.url(JWKS_PATH),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": self.known_scopes,
            "authorization_response_iss_parameter_supported": true,
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "service_documentation": "https://github.com/usergenic/host-my-mcp#readme",
        });
        if self.dynamic_registration {
            md["registration_endpoint"] = Value::String(self.url(REGISTER_PATH));
        }
        md
    }

    pub fn jwks(&self) -> Value {
        self.signer.jwks()
    }

    /// Map requested `resource` values to configured mounts. With exactly one
    /// mount configured, an omitted `resource` means that mount.
    pub fn resolve_resources(&self, requested: &[String]) -> Result<Vec<ResourceInfo>, String> {
        if requested.is_empty() {
            return match self.resources.as_slice() {
                [only] => Ok(vec![only.clone()]),
                _ => Err(format!(
                    "the `resource` parameter is required; one of: {}",
                    self.resources
                        .iter()
                        .map(|r| r.resource.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            };
        }
        let mut out: Vec<ResourceInfo> = Vec::new();
        for r in requested {
            let want = Value::String(r.clone());
            match self
                .resources
                .iter()
                .find(|info| audience_matches(Some(&want), &info.url))
            {
                Some(info) => {
                    if !out.iter().any(|o| o.resource == info.resource) {
                        out.push(info.clone());
                    }
                }
                None => {
                    return Err(format!("`{r}` is not a resource served by this gateway"));
                }
            }
        }
        Ok(out)
    }

    /// Scopes to grant: the requested ones the gateway knows about, or, when
    /// nothing was requested, whatever the target mounts advertise (so a
    /// server's `scopes:` requirement is satisfied for every admitted user).
    pub fn grant_scopes(&self, requested: &[String], resources: &[ResourceInfo]) -> Vec<String> {
        let mut out: Vec<String> = if requested.is_empty() {
            resources.iter().flat_map(|r| r.scopes.clone()).collect()
        } else {
            requested
                .iter()
                .filter(|s| self.known_scopes.contains(*s))
                .cloned()
                .collect()
        };
        out.sort();
        out.dedup();
        out
    }

    /// Mint an access token for `grant`; returns `(token, expires_in)`.
    pub fn mint_access_token(&self, grant: &Grant<'_>) -> anyhow::Result<(String, u64)> {
        let now = util::now();
        let mut claims = json!({
            "iss": self.issuer,
            "sub": grant.identity.subject,
            "aud": grant.resources,
            "iat": now,
            "nbf": now,
            "exp": now + self.access_ttl,
            "jti": util::random_token(16),
            "client_id": grant.client_id,
            "provider": grant.identity.provider,
            "user": grant.user,
        });
        if !grant.scopes.is_empty() {
            claims["scope"] = Value::String(grant.scopes.join(" "));
        }
        if let Some(e) = &grant.identity.email {
            claims["email"] = Value::String(e.clone());
            claims["email_verified"] = Value::Bool(grant.identity.email_verified);
        }
        if let Some(n) = &grant.identity.name {
            claims["name"] = Value::String(n.clone());
        }
        Ok((self.signer.sign(&claims)?, self.access_ttl))
    }

    /// Issue a refresh token for `grant`, expiring at `expires_at`
    /// (`None` = `refresh_ttl` from now). Rotation keeps the original expiry.
    pub fn issue_refresh_token(&self, grant: &Grant<'_>, expires_at: Option<u64>) -> String {
        let token = format!("hmr_{}", util::random_token(32));
        self.store.insert_refresh(
            util::hash_secret(&token),
            store::RefreshToken {
                client_id: grant.client_id.to_string(),
                scopes: grant.scopes.to_vec(),
                resources: grant.resources.to_vec(),
                identity: grant.identity.clone(),
                user: grant.user.to_string(),
                created_at: util::now(),
                expires_at: expires_at.unwrap_or_else(|| util::now() + self.refresh_ttl),
            },
        );
        token
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn providers(&self) -> &BTreeMap<String, Arc<UpstreamProvider>> {
        &self.providers
    }

    pub fn policy(&self) -> &dyn Authorizer {
        self.policy.as_ref()
    }

    pub fn dynamic_registration(&self) -> bool {
        self.dynamic_registration
    }

    /// Which configured servers back `resources` (for the consent page).
    pub fn server_names(&self, resources: &[String]) -> Vec<String> {
        self.resources
            .iter()
            .filter(|r| resources.contains(&r.resource))
            .map(|r| r.server.clone())
            .collect()
    }
}

/// Exact match, except that loopback `http` redirect URIs may use any port
/// (RFC 8252 §7.3: native apps bind an ephemeral port).
pub fn redirect_uri_matches(registered: &str, given: &str) -> bool {
    if registered == given {
        return true;
    }
    let (Ok(r), Ok(g)) = (Url::parse(registered), Url::parse(given)) else {
        return false;
    };
    r.scheme() == "http"
        && g.scheme() == "http"
        && crate::config::is_loopback_host(&r)
        && crate::config::is_loopback_host(&g)
        && r.host_str().map(str::to_ascii_lowercase) == g.host_str().map(str::to_ascii_lowercase)
        && r.path() == g.path()
        && r.query() == g.query()
}

/// RFC 7591 registration: `https://…`, `http://` on loopback only, or a
/// private-use scheme (`cursor://…`, `vscode://…`). No fragments.
pub fn redirect_uri_allowed(uri: &str) -> bool {
    let Ok(u) = Url::parse(uri) else {
        return false;
    };
    if u.fragment().is_some() || u.cannot_be_a_base() && u.scheme() != "urn" {
        return false;
    }
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => crate::config::is_loopback_host(&u),
        "javascript" | "data" | "file" | "blob" | "about" => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        assert!(redirect_uri_allowed(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(redirect_uri_allowed("http://localhost:6274/oauth/callback"));
        assert!(redirect_uri_allowed("http://127.0.0.1/cb"));
        assert!(redirect_uri_allowed(
            "cursor://anysphere.cursor-retrieval/oauth/callback"
        ));
        assert!(!redirect_uri_allowed("http://example.com/cb"));
        assert!(!redirect_uri_allowed("https://example.com/cb#frag"));
        assert!(!redirect_uri_allowed("javascript:alert(1)"));
        assert!(!redirect_uri_allowed("not a url"));

        assert!(redirect_uri_matches("https://a/cb", "https://a/cb"));
        assert!(!redirect_uri_matches("https://a/cb", "https://a/cb2"));
        assert!(redirect_uri_matches(
            "http://127.0.0.1:1234/cb",
            "http://127.0.0.1:9999/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1234/cb",
            "http://localhost:1234/cb"
        ));
        assert!(!redirect_uri_matches("https://a:1/cb", "https://a:2/cb"));
    }
}
