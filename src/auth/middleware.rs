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

use super::{metadata::challenge_header, token::TokenValidator};
use crate::{
    audit,
    policy::{Authorizer, Decision, Principal},
};

pub struct AuthLayerState {
    pub server: String,
    pub resource: Url,
    pub metadata_url: Url,
    pub scopes: Vec<String>,
    /// `None` when `auth.disabled: true`.
    pub validator: Option<Arc<TokenValidator>>,
    pub policy: Arc<dyn Authorizer>,
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
    let principal = match &st.validator {
        None => Principal::anonymous(),
        Some(validator) => {
            let token = match bearer(&req) {
                Ok(Some(t)) => t.to_string(),
                Ok(None) => {
                    audit::authn(&st.server, "challenge", None, None, "no bearer token");
                    return st.challenge(
                        StatusCode::UNAUTHORIZED,
                        None,
                        "unauthorized",
                        "bearer token required",
                    );
                }
                Err(()) => {
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
            };
            match validator.validate(&token, &st.resource).await {
                Ok(p) => p,
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
    };

    let mut principal = principal;
    principal.user = st
        .policy
        .resolve_user(&principal.subject, principal.email.as_deref());

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
