//! Authorization-server state.
//!
//! Durable (written to `<state_dir>/oauth-state.json` on every change):
//! registered clients, refresh tokens (hashed), remembered consents.
//! In memory only: pending authorization transactions and authorization
//! codes, both short-lived; a restart simply makes a client start the flow
//! again.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use super::util::now;

pub const STATE_FILE: &str = "oauth-state.json";
const PENDING_TTL: u64 = 10 * 60;
const MAX_CLIENTS: usize = 1000;
const MAX_PENDING: usize = 1000;

/// Default grace window (seconds) for refresh-token rotation replay, used
/// when a store is created without an explicit value (`in_memory`, tests).
/// Production stores take the window from `auth.refresh_token_rotation_grace_secs`.
pub const DEFAULT_ROTATION_GRACE_SECS: u64 = 60;

/// A registered OAuth client (RFC 7591).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    /// `hash_secret(secret)`; `None` for public clients.
    #[serde(default)]
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    pub token_endpoint_auth_method: String,
    pub created_at: u64,
    pub last_used_at: u64,
    /// The registration response as returned to the client.
    pub metadata: serde_json::Value,
}

impl Client {
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none"
    }
    pub fn display_name(&self) -> String {
        self.client_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("client {}", &self.client_id[..self.client_id.len().min(8)]))
    }
}

/// Who signed in upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// `<provider>|<upstream sub>`, the policy key.
    pub subject: String,
    pub provider: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// An authorization request waiting for the upstream login and consent.
#[derive(Debug, Clone)]
pub struct Pending {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub provider: Option<String>,
    /// PKCE verifier and nonce used towards the upstream provider.
    pub upstream_verifier: String,
    pub nonce: String,
    pub created_at: u64,
    /// Set once the upstream login completed.
    pub identity: Option<Identity>,
    /// Name under `users` the identity resolved to.
    pub user: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub identity: Identity,
    pub user: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub identity: Identity,
    pub user: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// What a rotated refresh token was replaced by, and when. Only entries
/// younger than the store's rotation grace window are honoured; `sweep()`
/// prunes the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedRefresh {
    pub new_hash: String,
    pub rotated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    pub subject: String,
    pub client_id: String,
    pub granted_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    clients: BTreeMap<String, Client>,
    /// Keyed by `hash_secret(refresh_token)`.
    #[serde(default)]
    refresh_tokens: BTreeMap<String, RefreshToken>,
    /// Keyed by `hash_secret(old_refresh_token)`.
    #[serde(default)]
    rotated_refresh_tokens: BTreeMap<String, RotatedRefresh>,
    #[serde(default)]
    consents: Vec<Consent>,
}

#[derive(Default)]
struct Inner {
    persisted: Persisted,
    pending: HashMap<String, Pending>,
    codes: HashMap<String, AuthCode>,
}

pub struct Store {
    path: Option<PathBuf>,
    /// Seconds a rotated refresh token may be replayed to recover a lost
    /// rotation response; `0` disables the grace window entirely.
    rotation_grace: u64,
    inner: Mutex<Inner>,
}

impl Store {
    /// Open (or create) the state file under `dir`, honouring rotated refresh
    /// tokens for `rotation_grace` seconds (`0` disables the grace window).
    pub fn open(dir: &Path, rotation_grace: u64) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("cannot create state_dir {}: {e}", dir.display()))?;
        let path = dir.join(STATE_FILE);
        let persisted = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                anyhow::anyhow!(
                    "{} is corrupt: {e} (move it aside to start fresh)",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(e) => return Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
        };
        let store = Self {
            path: Some(path),
            rotation_grace,
            inner: Mutex::new(Inner {
                persisted,
                ..Default::default()
            }),
        };
        store.sweep();
        Ok(store)
    }

    /// Volatile store (tests), with the default rotation grace window.
    pub fn in_memory() -> Self {
        Self::in_memory_with_grace(DEFAULT_ROTATION_GRACE_SECS)
    }

    /// Volatile store (tests) with an explicit rotation grace window.
    pub fn in_memory_with_grace(rotation_grace: u64) -> Self {
        Self {
            path: None,
            rotation_grace,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }

    /// Mutate durable state and write it out.
    fn persist<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> R {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let r = f(&mut g.persisted);
        if let Some(path) = &self.path
            && let Err(e) = write_atomic(path, &g.persisted)
        {
            tracing::error!(path = %path.display(), error = %e, "could not persist OAuth state");
        }
        r
    }

    /// Drop expired codes, pending transactions and refresh tokens.
    pub fn sweep(&self) {
        let t = now();
        let grace = self.rotation_grace;
        let changed = self.with(|i| {
            i.pending.retain(|_, p| t < p.created_at + PENDING_TTL);
            i.codes.retain(|_, c| t < c.expires_at);
            let before =
                i.persisted.refresh_tokens.len() + i.persisted.rotated_refresh_tokens.len();
            i.persisted.refresh_tokens.retain(|_, r| t < r.expires_at);
            i.persisted
                .rotated_refresh_tokens
                .retain(|_, r| t < r.rotated_at + grace);
            before != i.persisted.refresh_tokens.len() + i.persisted.rotated_refresh_tokens.len()
        });
        if changed {
            self.persist(|_| ());
        }
    }

    // ----- clients -----

    pub fn insert_client(&self, client: Client) {
        self.persist(|p| {
            if p.clients.len() >= MAX_CLIENTS {
                // Evict the least recently used registration.
                if let Some(victim) = p
                    .clients
                    .iter()
                    .min_by_key(|(_, c)| c.last_used_at)
                    .map(|(id, _)| id.clone())
                {
                    p.clients.remove(&victim);
                }
            }
            p.clients.insert(client.client_id.clone(), client);
        });
    }

    pub fn client(&self, id: &str) -> Option<Client> {
        self.with(|i| i.persisted.clients.get(id).cloned())
    }

    pub fn touch_client(&self, id: &str) {
        let t = now();
        self.persist(|p| {
            if let Some(c) = p.clients.get_mut(id) {
                c.last_used_at = t;
            }
        });
    }

    // ----- pending authorizations -----

    pub fn insert_pending(&self, pending: Pending) {
        self.with(|i| {
            let t = now();
            i.pending.retain(|_, p| t < p.created_at + PENDING_TTL);
            if i.pending.len() >= MAX_PENDING
                && let Some(oldest) = i
                    .pending
                    .iter()
                    .min_by_key(|(_, p)| p.created_at)
                    .map(|(k, _)| k.clone())
            {
                i.pending.remove(&oldest);
            }
            i.pending.insert(pending.id.clone(), pending);
        });
    }

    pub fn pending(&self, id: &str) -> Option<Pending> {
        self.with(|i| {
            i.pending
                .get(id)
                .filter(|p| now() < p.created_at + PENDING_TTL)
                .cloned()
        })
    }

    pub fn update_pending(&self, pending: Pending) {
        self.with(|i| {
            i.pending.insert(pending.id.clone(), pending);
        });
    }

    pub fn take_pending(&self, id: &str) -> Option<Pending> {
        self.with(|i| {
            i.pending
                .remove(id)
                .filter(|p| now() < p.created_at + PENDING_TTL)
        })
    }

    // ----- authorization codes -----

    pub fn insert_code(&self, code: String, auth: AuthCode) {
        self.with(|i| {
            let t = now();
            i.codes.retain(|_, c| t < c.expires_at);
            i.codes.insert(code, auth);
        });
    }

    /// One-time redemption.
    pub fn consume_code(&self, code: &str) -> Option<AuthCode> {
        self.with(|i| i.codes.remove(code).filter(|c| now() < c.expires_at))
    }

    // ----- refresh tokens -----

    pub fn insert_refresh(&self, token_hash: String, rt: RefreshToken) {
        self.persist(|p| {
            p.refresh_tokens.insert(token_hash, rt);
        });
    }

    /// One-time redemption (rotation): the caller stores the replacement.
    pub fn consume_refresh(&self, token_hash: &str) -> Option<RefreshToken> {
        self.persist(|p| {
            p.refresh_tokens
                .remove(token_hash)
                .filter(|r| now() < r.expires_at)
        })
    }

    /// Record that `old_hash` was rotated into `new_hash` at `now()`.
    /// Stale entries (older than the grace window) are pruned on the way.
    pub fn record_rotation(&self, old_hash: &str, new_hash: &str) {
        let grace = self.rotation_grace;
        if grace == 0 {
            // Grace disabled: strict one-time rotation, nothing to remember.
            return;
        }
        let t = now();
        self.persist(|p| {
            p.rotated_refresh_tokens
                .retain(|_, r| t < r.rotated_at + grace);
            p.rotated_refresh_tokens.insert(
                old_hash.to_string(),
                RotatedRefresh {
                    new_hash: new_hash.to_string(),
                    rotated_at: t,
                },
            );
        });
    }

    /// Recover from a lost rotation response: if `old_hash` was rotated
    /// within the grace window, consume the replacement token and return
    /// its record, so the caller can mint a fresh pair from it. Follows
    /// the rotation chain if the replacement was itself rotated (a second
    /// dropped response inside the window). Returns `None` once the
    /// window lapses or the chain ends in a token already consumed
    /// elsewhere.
    pub fn consume_rotated(&self, old_hash: &str) -> Option<RefreshToken> {
        let grace = self.rotation_grace;
        if grace == 0 {
            return None;
        }
        let mut hash = old_hash.to_string();
        for _ in 0..8 {
            let next = self.with(|i| {
                i.persisted
                    .rotated_refresh_tokens
                    .get(&hash)
                    .filter(|r| now() < r.rotated_at + grace)
                    .map(|r| r.new_hash.clone())
            })?;
            match self.consume_refresh(&next) {
                Some(rt) => return Some(rt),
                // Replacement already consumed; follow its rotation, if any.
                None => hash = next,
            }
        }
        None
    }

    /// Revoke every refresh token issued to `client_id` for `subject`
    /// (used when a rotated token is replayed, per OAuth 2.1 §4.3.1).
    pub fn revoke_refresh_for(&self, client_id: &str, subject: &str) -> usize {
        self.persist(|p| {
            let before = p.refresh_tokens.len();
            p.refresh_tokens
                .retain(|_, r| !(r.client_id == client_id && r.identity.subject == subject));
            before - p.refresh_tokens.len()
        })
    }

    // ----- consents -----

    pub fn has_consent(&self, subject: &str, client_id: &str) -> bool {
        self.with(|i| {
            i.persisted
                .consents
                .iter()
                .any(|c| c.subject == subject && c.client_id == client_id)
        })
    }

    pub fn grant_consent(&self, subject: &str, client_id: &str) {
        if self.has_consent(subject, client_id) {
            return;
        }
        self.persist(|p| {
            p.consents.push(Consent {
                subject: subject.to_string(),
                client_id: client_id.to_string(),
                granted_at: now(),
            });
        });
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        self.with(|i| {
            (
                i.persisted.clients.len(),
                i.persisted.refresh_tokens.len(),
                i.persisted.consents.len(),
            )
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

fn write_atomic(path: &Path, value: &Persisted) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            subject: "google|1".into(),
            provider: "google".into(),
            email: Some("a@b.c".into()),
            email_verified: true,
            name: None,
        }
    }

    #[test]
    fn persists_clients_refresh_and_consent_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Store::open(dir.path(), DEFAULT_ROTATION_GRACE_SECS).unwrap();
            s.insert_client(Client {
                client_id: "c1".into(),
                client_secret_hash: None,
                redirect_uris: vec!["https://x/cb".into()],
                client_name: Some("X".into()),
                client_uri: None,
                token_endpoint_auth_method: "none".into(),
                created_at: 1,
                last_used_at: 1,
                metadata: serde_json::json!({}),
            });
            s.insert_refresh(
                "h1".into(),
                RefreshToken {
                    client_id: "c1".into(),
                    scopes: vec![],
                    resources: vec!["https://r/a".into()],
                    identity: identity(),
                    user: "u".into(),
                    created_at: now(),
                    expires_at: now() + 100,
                },
            );
            s.grant_consent("google|1", "c1");
        }
        let s = Store::open(dir.path(), DEFAULT_ROTATION_GRACE_SECS).unwrap();
        assert!(s.client("c1").unwrap().is_public());
        assert!(s.has_consent("google|1", "c1"));
        assert!(s.consume_refresh("h1").is_some());
        assert!(s.consume_refresh("h1").is_none(), "one-time redemption");
    }

    #[test]
    fn rotated_token_replays_inside_grace_window() {
        let s = Store::in_memory();
        let t = now();
        let grant = RefreshToken {
            client_id: "c1".into(),
            scopes: vec![],
            resources: vec!["https://r/a".into()],
            identity: identity(),
            user: "u".into(),
            created_at: t,
            expires_at: t + 1000,
        };
        s.insert_refresh("h-old".into(), grant.clone());
        s.insert_refresh("h-new".into(), grant);
        // Rotation: old token consumed, replacement recorded.
        assert!(s.consume_refresh("h-old").is_some());
        s.record_rotation("h-old", "h-new");
        // Replay of the old token recovers the replacement...
        let recovered = s.consume_rotated("h-old");
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().client_id, "c1");
        // ...and the replacement is now consumed, so a second replay
        // finds nothing live.
        assert!(s.consume_rotated("h-old").is_none());
    }

    #[test]
    fn unknown_token_still_rejected() {
        let s = Store::in_memory();
        assert!(s.consume_rotated("h-nope").is_none());
        assert!(s.consume_refresh("h-nope").is_none());
    }

    #[test]
    fn zero_grace_disables_replay() {
        let s = Store::in_memory_with_grace(0);
        let t = now();
        let grant = RefreshToken {
            client_id: "c1".into(),
            scopes: vec![],
            resources: vec!["https://r/a".into()],
            identity: identity(),
            user: "u".into(),
            created_at: t,
            expires_at: t + 1000,
        };
        s.insert_refresh("h-old".into(), grant.clone());
        s.insert_refresh("h-new".into(), grant);
        assert!(s.consume_refresh("h-old").is_some());
        s.record_rotation("h-old", "h-new");
        // Grace disabled: the old token cannot recover its replacement...
        assert!(s.consume_rotated("h-old").is_none());
        // ...and the replacement is untouched, still live.
        assert!(s.consume_refresh("h-new").is_some());
    }

    #[test]
    fn codes_are_single_use_and_expire() {
        let s = Store::in_memory();
        let code = AuthCode {
            client_id: "c".into(),
            redirect_uri: "https://x/cb".into(),
            code_challenge: "ch".into(),
            scopes: vec![],
            resources: vec![],
            identity: identity(),
            user: "u".into(),
            expires_at: now() + 60,
        };
        s.insert_code("k".into(), code.clone());
        assert!(s.consume_code("k").is_some());
        assert!(s.consume_code("k").is_none());
        let mut expired = code;
        expired.expires_at = now() - 1;
        s.insert_code("e".into(), expired);
        assert!(s.consume_code("e").is_none());
    }
}
