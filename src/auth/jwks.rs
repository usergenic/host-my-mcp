//! JWKS retrieval and caching with fail-closed semantics.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::{DecodingKey, jwk::JwkSet};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use url::Url;

#[derive(Debug, Error)]
pub enum JwksError {
    #[error("JWKS fetch failed: {0}")]
    Fetch(String),
    #[error("JWKS document invalid: {0}")]
    Invalid(String),
    #[error("no signing key with kid `{0}`")]
    UnknownKid(String),
    #[error("key `{0}` cannot be used: {1}")]
    UnusableKey(String, String),
}

/// Source of signing keys. Implemented by the HTTP-backed cache and by static
/// key sets in tests.
#[async_trait::async_trait]
pub trait KeySource: Send + Sync + 'static {
    /// Return the decoding key for `kid`, refreshing if it is unknown and the
    /// refresh policy permits.
    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError>;
}

struct Cached {
    set: JwkSet,
    fetched_at: Instant,
}

/// Fetches `jwks_uri` over HTTPS, caches it, refreshes on unknown `kid`
/// (rate-limited) and when the cache is older than `max_age`.
pub struct JwksCache {
    uri: Url,
    client: reqwest::Client,
    cache: RwLock<Option<Cached>>,
    refresh_lock: Mutex<Option<Instant>>,
    min_refresh: Duration,
    max_age: Duration,
}

impl JwksCache {
    pub fn new(uri: Url, min_refresh: Duration, max_age: Duration) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("host-my-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Arc::new(Self {
            uri,
            client,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(None),
            min_refresh,
            max_age,
        })
    }

    /// Fetch now (used at startup so a misconfigured issuer fails fast).
    pub async fn warm(&self) -> Result<usize, JwksError> {
        self.refresh(true).await?;
        Ok(self
            .cache
            .read()
            .await
            .as_ref()
            .map(|c| c.set.keys.len())
            .unwrap_or(0))
    }

    async fn refresh(&self, force: bool) -> Result<(), JwksError> {
        let mut guard = self.refresh_lock.lock().await;
        if !force
            && let Some(last) = *guard
            && last.elapsed() < self.min_refresh
        {
            // Another caller refreshed moments ago; the key is simply unknown.
            return Ok(());
        }
        tracing::debug!(uri = %self.uri, "refreshing JWKS");
        let resp = self
            .client
            .get(self.uri.clone())
            .send()
            .await
            .map_err(|e| JwksError::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(JwksError::Fetch(format!("HTTP {}", resp.status())));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| JwksError::Invalid(e.to_string()))?;
        if set.keys.is_empty() {
            return Err(JwksError::Invalid("empty key set".into()));
        }
        *self.cache.write().await = Some(Cached {
            set,
            fetched_at: Instant::now(),
        });
        *guard = Some(Instant::now());
        Ok(())
    }

    async fn lookup(&self, kid: &str) -> Option<Result<Arc<DecodingKey>, JwksError>> {
        let cache = self.cache.read().await;
        let cached = cache.as_ref()?;
        let jwk = cached.set.find(kid)?;
        Some(
            DecodingKey::from_jwk(jwk)
                .map(Arc::new)
                .map_err(|e| JwksError::UnusableKey(kid.to_string(), e.to_string())),
        )
    }

    async fn is_stale(&self) -> bool {
        match self.cache.read().await.as_ref() {
            Some(c) => c.fetched_at.elapsed() > self.max_age,
            None => true,
        }
    }
}

#[async_trait::async_trait]
impl KeySource for JwksCache {
    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        if !self.is_stale().await
            && let Some(found) = self.lookup(kid).await
        {
            return found;
        }
        // Unknown kid or stale cache: refresh (rate-limited) and retry once.
        // If the refresh fails and we still hold keys, fall back to them so a
        // transient issuer outage does not break tokens signed by known keys,
        // but never accept an unknown key without a successful refresh.
        if let Err(e) = self.refresh(false).await {
            tracing::warn!(error = %e, "JWKS refresh failed");
            return match self.lookup(kid).await {
                Some(found) => found,
                None => Err(e),
            };
        }
        self.lookup(kid)
            .await
            .unwrap_or_else(|| Err(JwksError::UnknownKid(kid.to_string())))
    }
}

/// A fixed key set (tests, or air-gapped deployments that pin keys).
pub struct StaticKeys {
    set: JwkSet,
}

impl StaticKeys {
    pub fn from_json(json: &str) -> Result<Arc<Self>, JwksError> {
        let set: JwkSet =
            serde_json::from_str(json).map_err(|e| JwksError::Invalid(e.to_string()))?;
        Ok(Arc::new(Self { set }))
    }
}

#[async_trait::async_trait]
impl KeySource for StaticKeys {
    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        let jwk = self
            .set
            .find(kid)
            .ok_or_else(|| JwksError::UnknownKid(kid.to_string()))?;
        DecodingKey::from_jwk(jwk)
            .map(Arc::new)
            .map_err(|e| JwksError::UnusableKey(kid.to_string(), e.to_string()))
    }
}
