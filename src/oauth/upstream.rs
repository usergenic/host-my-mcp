//! The upstream OpenID Connect provider (Google, …) used for the human login
//! step. The gateway is an ordinary confidential OIDC client here: discovery,
//! Authorization Code + PKCE + nonce, ID token verification against the
//! provider's JWKS.

use std::{sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use super::{store::Identity, util::urlencode};
use crate::{
    auth::jwks::{JwksCache, KeySource},
    config::Provider,
};

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("provider returned an error: {0}")]
    Provider(String),
    #[error("token exchange failed: {0}")]
    Exchange(String),
    #[error("ID token invalid: {0}")]
    IdToken(String),
    #[error("email address is not verified by the provider")]
    EmailUnverified,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

pub struct UpstreamProvider {
    pub name: String,
    pub display_name: String,
    cfg: Provider,
    discovery: Discovery,
    keys: Arc<JwksCache>,
    http: reqwest::Client,
    algorithms: Vec<Algorithm>,
}

impl UpstreamProvider {
    /// Fetch `<issuer>/.well-known/openid-configuration` and prepare the
    /// provider. Fails fast so a typo in the issuer is caught at startup.
    pub async fn discover(name: &str, cfg: &Provider) -> anyhow::Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("host-my-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let mut url = cfg.issuer.clone();
        let base = url.path().trim_end_matches('/').to_string();
        url.set_path(&format!("{base}/.well-known/openid-configuration"));
        let discovery: Discovery = http
            .get(url.clone())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("provider `{name}`: discovery {url} failed: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("provider `{name}`: discovery {url}: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("provider `{name}`: discovery document invalid: {e}"))?;
        let mut algorithms: Vec<Algorithm> = discovery
            .id_token_signing_alg_values_supported
            .iter()
            .filter_map(|a| a.parse().ok())
            .filter(|a| !matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512))
            .collect();
        if algorithms.is_empty() {
            algorithms = vec![Algorithm::RS256];
        }
        let keys = JwksCache::new(
            discovery.jwks_uri.clone(),
            Duration::from_secs(30),
            Duration::from_secs(6 * 3600),
        );
        if let Err(e) = keys.warm().await {
            tracing::warn!(provider = %name, error = %e, "could not prefetch provider JWKS; will retry at first login");
        }
        tracing::info!(provider = %name, issuer = %discovery.issuer, "identity provider ready");
        Ok(Arc::new(Self {
            name: name.to_string(),
            display_name: cfg
                .display_name
                .clone()
                .unwrap_or_else(|| default_display_name(name)),
            cfg: cfg.clone(),
            discovery,
            keys,
            http,
            algorithms,
        }))
    }

    /// Where to send the browser.
    pub fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Url {
        let mut u = self.discovery.authorization_endpoint.clone();
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &self.cfg.scopes.join(" "))
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
        }
        u
    }

    /// Redeem the provider's code and verify the ID token.
    pub async fn exchange(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
        nonce: &str,
    ) -> Result<Identity, UpstreamError> {
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            urlencode(code),
            urlencode(redirect_uri),
            urlencode(&self.cfg.client_id),
            urlencode(&self.cfg.client_secret),
            urlencode(code_verifier),
        );
        let resp = self
            .http
            .post(self.discovery.token_endpoint.clone())
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| UpstreamError::Exchange(e.to_string()))?;
        let status = resp.status();
        let json: Value = resp
            .json()
            .await
            .map_err(|e| UpstreamError::Exchange(format!("non-JSON response: {e}")))?;
        if !status.is_success() {
            let err = json["error"].as_str().unwrap_or("unknown_error");
            let desc = json["error_description"].as_str().unwrap_or("");
            return Err(UpstreamError::Exchange(format!("{status}: {err} {desc}")));
        }
        let id_token = json["id_token"]
            .as_str()
            .ok_or_else(|| UpstreamError::Exchange("response has no id_token".into()))?;
        self.verify_id_token(id_token, nonce).await
    }

    async fn verify_id_token(&self, token: &str, nonce: &str) -> Result<Identity, UpstreamError> {
        let header = decode_header(token).map_err(|e| UpstreamError::IdToken(e.to_string()))?;
        if !self.algorithms.contains(&header.alg) {
            return Err(UpstreamError::IdToken(format!(
                "unsupported alg {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| UpstreamError::IdToken("no kid".into()))?;
        let key = self
            .keys
            .key_for(&kid)
            .await
            .map_err(|e| UpstreamError::IdToken(e.to_string()))?;
        let mut v = Validation::new(header.alg);
        v.algorithms = self.algorithms.clone();
        v.leeway = 60;
        v.set_audience(&[self.cfg.client_id.as_str()]);
        // Google historically issued `iss` both with and without the scheme.
        let iss = self.discovery.issuer.trim_end_matches('/').to_string();
        let bare = iss
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string();
        v.set_issuer(&[iss.as_str(), format!("{iss}/").as_str(), bare.as_str()]);
        v.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
        let data = decode::<Map<String, Value>>(token, &key, &v)
            .map_err(|e| UpstreamError::IdToken(e.to_string()))?;
        let c = data.claims;
        if c.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err(UpstreamError::IdToken("nonce mismatch".into()));
        }
        let sub = c
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| UpstreamError::IdToken("no sub".into()))?;
        let email = c
            .get("email")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let email_verified = match c.get("email_verified") {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
            _ => false,
        };
        if self.cfg.require_verified_email && email.is_some() && !email_verified {
            return Err(UpstreamError::EmailUnverified);
        }
        let name = c
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        Ok(Identity {
            subject: format!("{}|{}", self.name, sub),
            provider: self.name.clone(),
            email: if email_verified || !self.cfg.require_verified_email {
                email
            } else {
                None
            },
            email_verified,
            name,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.discovery.issuer
    }
}

fn default_display_name(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => name.to_string(),
    }
}
