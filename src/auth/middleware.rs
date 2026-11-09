//! axum middleware guarding one MCP mount.
//!
//! Order of checks (fail closed):
//! 1. `Authorization: Bearer <token>` present, else 401 + challenge.
//! 2. Token validates for this server's resource, else 401 (or 503 if the
//!    signing keys cannot be fetched).
//! 3. Subject/email resolves to a configured user and the policy admits that
//!    user to this server (including required scopes), else 403.
//! 4. The [`Principal`] is attached to the request so the MCP handler can make
//!    per-tool decisions.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

use std::collections::BTreeMap;

use super::{metadata::challenge_header, token::TokenValidator};
use crate::{
    audit,
    config::ServiceToken,
    oauth::util::hash_secret,
    policy::{Authorizer, Decision, Principal},
};

/// The identity a matched static service token resolves to.
struct ServiceIdentity {
    subject: String,
    user: String,
    scopes: Vec<String>,
}

/// Static bearer tokens for non-interactive services (`auth.service_tokens`),
/// indexed by `hash_secret(token)` so the raw secrets are not held in memory.
#[derive(Default)]
pub struct ServiceTokens {
    by_hash: std::collections::HashMap<String, ServiceIdentity>,
}

impl ServiceTokens {
    /// Build the lookup from config. The map key names the service and becomes
    /// the token's synthetic subject (`service|<name>`).
    pub fn from_config(tokens: &BTreeMap<String, ServiceToken>) -> Self {
        let by_hash = tokens
            .iter()
            .map(|(name, t)| {
                (
                    hash_secret(&t.token),
                    ServiceIdentity {
                        subject: format!("service|{name}"),
                        user: t.user.clone(),
                        scopes: t.scopes.clone(),
                    },
                )
            })
            .collect();
        Self { by_hash }
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Resolve a presented bearer token to its service principal, if it is one.
    /// The lookup is keyed by the token's hash, so a miss reveals nothing about
    /// any configured secret.
    fn principal_for(&self, token: &str) -> Option<Principal> {
        let id = self.by_hash.get(&hash_secret(token))?;
        Some(Principal {
            subject: id.subject.clone(),
            email: None,
            // A static token carries its own identity; do not re-resolve it.
            user: Some(id.user.clone()),
            scopes: id.scopes.clone(),
            claims: Default::default(),
        })
    }
}

pub struct AuthLayerState {
    pub server: String,
    pub resource: Url,
    pub metadata_url: Url,
    pub scopes: Vec<String>,
    /// `None` when `auth.disabled: true`.
    pub validator: Option<Arc<TokenValidator>>,
    pub policy: Arc<dyn Authorizer>,
    /// Static service tokens, shared across mounts; empty when none configured.
    pub service_tokens: Arc<ServiceTokens>,
}

impl AuthLayerState {
    fn challenge(
        &self,
        status: StatusCode,
        error: Option<(&str, &str)>,
        body_error: &str,
        detail: &str,
    ) -> Response {
        let www = challenge_header(&self.metadata_url, &self.scopes, error);
        let body = serde_json::json!({ "error": body_error, "error_description": detail });
        let mut resp = (status, axum::Json(body)).into_response();
        if let Ok(v) = HeaderValue::from_str(&www) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        resp
    }
}

fn bearer(req: &Request<Body>) -> Result<Option<&str>, ()> {
    let Some(h) = req.headers().get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let s = h.to_str().map_err(|_| ())?;
    let (scheme, rest) = s.split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(());
    }
    let tok = rest.trim();
    if tok.is_empty() {
        return Err(());
    }
    Ok(Some(tok))
}

pub async fn require_auth(
    State(st): State<Arc<AuthLayerState>>,
    mut req: Request,
    next: Next,
) -> Response {
    // A malformed `Authorization` header is rejected whenever authentication is
    // in force; in fully-open mode (no validator and no service tokens) it is
    // ignored, as before.
    let has_auth = st.validator.is_some() || !st.service_tokens.is_empty();
    let bearer_token: Option<String> = match bearer(&req).map(|o| o.map(str::to_string)) {
        Ok(t) => t,
        Err(()) if has_auth => {
            audit::authn(
                &st.server,
                "reject",
                None,
                None,
                "malformed authorization header",
            );
            return st.challenge(
                StatusCode::UNAUTHORIZED,
                Some(("invalid_request", "malformed Authorization header")),
                "invalid_request",
                "malformed Authorization header",
            );
        }
        Err(()) => None,
    };

    // A static service token carries its own identity and is honoured in every
    // auth mode; `resolve_user` then only applies to validated OAuth tokens.
    let service_principal = bearer_token
        .as_deref()
        .and_then(|t| st.service_tokens.principal_for(t));

    let (mut principal, resolve_user) = match service_principal {
        Some(p) => (p, false),
        None => match &st.validator {
            None => (Principal::anonymous(), true),
            Some(validator) => {
                let Some(token) = bearer_token else {
                    audit::authn(&st.server, "challenge", None, None, "no bearer token");
                    return st.challenge(
                        StatusCode::UNAUTHORIZED,
                        None,
                        "unauthorized",
                        "bearer token required",
                    );
                };
                match validator.validate(&token, &st.resource).await {
                    Ok(p) => (p, true),
                    Err(e) if e.is_server_side() => {
                        tracing::error!(server = %st.server, error = %e, "token validation unavailable; failing closed");
                        audit::authn(&st.server, "unavailable", None, None, &e.to_string());
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(serde_json::json!({"error": "temporarily_unavailable", "error_description": "token validation unavailable"})),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        audit::authn(&st.server, "reject", None, None, &e.to_string());
                        // Do not echo claim contents back; the category is enough for clients.
                        return st.challenge(
                            StatusCode::UNAUTHORIZED,
                            Some(("invalid_token", "token is not valid for this resource")),
                            "invalid_token",
                            "token is not valid for this resource",
                        );
                    }
                }
            }
        },
    };

    if resolve_user {
        principal.user = st
            .policy
            .resolve_user(&principal.subject, principal.email.as_deref());
    }

    match st.policy.authorize_server(&principal, &st.server) {
        Decision::Allow { reason } => {
            audit::authn(
                &st.server,
                "allow",
                Some(&principal.subject),
                principal.user.as_deref(),
                &reason,
            );
        }
        Decision::Deny { reason } => {
            audit::authn(
                &st.server,
                "deny",
                Some(&principal.subject),
                principal.user.as_deref(),
                &reason,
            );
            let insufficient_scope = reason.starts_with("missing required scope");
            return if insufficient_scope {
                st.challenge(
                    StatusCode::FORBIDDEN,
                    Some(("insufficient_scope", "additional scope required")),
                    "insufficient_scope",
                    "additional scope required",
                )
            } else {
                (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"error": "access_denied", "error_description": "identity is not permitted to use this server"})),
                )
                    .into_response()
            };
        }
    }

    req.extensions_mut().insert(principal);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_token_resolves_to_its_identity() {
        let mut map = BTreeMap::new();
        map.insert(
            "ci".to_string(),
            ServiceToken {
                token: "secret".into(),
                user: "ci-bot".into(),
                scopes: vec!["omg:use".into()],
            },
        );
        let st = ServiceTokens::from_config(&map);
        assert!(!st.is_empty());

        let p = st.principal_for("secret").expect("matching token");
        assert_eq!(p.subject, "service|ci");
        assert_eq!(p.user.as_deref(), Some("ci-bot"));
        assert_eq!(p.scopes, vec!["omg:use".to_string()]);

        assert!(st.principal_for("wrong").is_none());
    }

    #[test]
    fn empty_when_unconfigured() {
        assert!(ServiceTokens::from_config(&BTreeMap::new()).is_empty());
        assert!(ServiceTokens::default().principal_for("anything").is_none());
    }
}
