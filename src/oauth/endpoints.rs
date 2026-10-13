//! HTTP handlers for the built-in authorization server.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde_json::{Value, json};
use url::Url;

use super::{
    AUTHORIZE_PATH, AuthorizationServer, CONSENT_PATH, Grant, html, redirect_uri_allowed,
    redirect_uri_matches,
    store::{AuthCode, Client, Pending},
    util::{self, hash_secret, now, random_token},
};
use crate::{audit, policy::Principal};

type Server = State<Arc<AuthorizationServer>>;

const AUDIT_SERVER: &str = "oauth";
const CODE_TTL: u64 = 5 * 60;

// ----- small helpers -----

struct Params(Vec<(String, String)>);

impl Params {
    fn from_query(q: Option<String>) -> Self {
        Self(
            url::form_urlencoded::parse(q.unwrap_or_default().as_bytes())
                .into_owned()
                .collect(),
        )
    }
    fn from_form(body: &[u8]) -> Self {
        Self(url::form_urlencoded::parse(body).into_owned().collect())
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
    fn all(&self, key: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
            .collect()
    }
    fn scopes(&self) -> Vec<String> {
        self.get("scope")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({ "error": error, "error_description": description })),
        )
            .into_response(),
    )
}

fn redirect(location: &str) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    no_store(resp)
}

/// Append query parameters to a client redirect URI (keeps existing query).
fn with_params(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    match Url::parse(redirect_uri) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in params {
                    q.append_pair(k, v);
                }
            }
            u.to_string()
        }
        Err(_) => {
            let sep = if redirect_uri.contains('?') { '&' } else { '?' };
            let qs: Vec<String> = params
                .iter()
                .map(|(k, v)| format!("{}={}", util::urlencode(k), util::urlencode(v)))
                .collect();
            format!("{redirect_uri}{sep}{}", qs.join("&"))
        }
    }
}

fn error_redirect_url(
    issuer: &str,
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> String {
    let mut params = vec![
        ("error", error),
        ("error_description", description),
        ("iss", issuer),
    ];
    if let Some(s) = state {
        params.push(("state", s));
    }
    with_params(redirect_uri, &params)
}

fn identity_label(p: &Pending) -> String {
    match &p.identity {
        Some(id) => id
            .email
            .clone()
            .or_else(|| id.name.clone())
            .unwrap_or_else(|| id.subject.clone()),
        None => "unknown".into(),
    }
}

// ----- discovery -----

pub async fn metadata(State(s): Server) -> Response {
    let mut resp = Json(s.metadata()).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

pub async fn jwks(State(s): Server) -> Response {
    let mut resp = Json(s.jwks()).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

// ----- RFC 7591 dynamic client registration -----

pub async fn register(State(s): Server, body: Bytes) -> Response {
    if !s.dynamic_registration() {
        return json_error(
            StatusCode::FORBIDDEN,
            "invalid_request",
            "dynamic client registration is disabled on this gateway",
        );
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v @ Value::Object(_)) => v,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "request body must be a JSON object",
            );
        }
    };
    let redirect_uris: Vec<String> = match req.get("redirect_uris") {
        Some(Value::Array(a)) if !a.is_empty() => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uris must be a non-empty array of strings",
            );
        }
    };
    for u in &redirect_uris {
        if !redirect_uri_allowed(u) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                &format!(
                    "redirect_uri `{u}` is not acceptable (use https, http on localhost/127.0.0.1, or a private-use scheme; no fragments)"
                ),
            );
        }
    }
    let auth_method = req
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
        .to_string();
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post"
    ) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post",
        );
    }
    let grant_types: Vec<String> = match req.get("grant_types") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => vec!["authorization_code".into(), "refresh_token".into()],
    };
    if grant_types
        .iter()
        .any(|g| !matches!(g.as_str(), "authorization_code" | "refresh_token"))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only the authorization_code and refresh_token grant types are supported",
        );
    }
    if let Some(Value::Array(rt)) = req.get("response_types")
        && rt.iter().any(|r| r.as_str() != Some("code"))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only the code response type is supported",
        );
    }
    let str_field = |k: &str| {
        req.get(k)
            .and_then(Value::as_str)
            .map(|v| v.chars().take(200).collect::<String>())
            .filter(|v| !v.trim().is_empty())
    };
    let client_name = str_field("client_name");
    let client_uri = str_field("client_uri").filter(|u| {
        Url::parse(u)
            .map(|p| matches!(p.scheme(), "http" | "https"))
            .unwrap_or(false)
    });

    let client_id = format!("hmc_{}", random_token(18));
    let secret = (auth_method != "none").then(|| format!("hms_{}", random_token(32)));
    let created = now();
    let mut metadata = json!({
        "client_id": client_id,
        "client_id_issued_at": created,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": auth_method,
        "grant_types": grant_types,
        "response_types": ["code"],
    });
    if let Some(sec) = &secret {
        metadata["client_secret"] = Value::String(sec.clone());
        metadata["client_secret_expires_at"] = json!(0);
    }
    for k in [
        "client_name",
        "client_uri",
        "logo_uri",
        "scope",
        "contacts",
        "tos_uri",
        "policy_uri",
        "software_id",
        "software_version",
    ] {
        if let Some(v) = req.get(k) {
            metadata[k] = v.clone();
        }
    }
    s.store().insert_client(Client {
        client_id: client_id.clone(),
        client_secret_hash: secret.as_deref().map(hash_secret),
        redirect_uris,
        client_name: client_name.clone(),
        client_uri,
        token_endpoint_auth_method: auth_method,
        created_at: created,
        last_used_at: created,
        metadata: metadata.clone(),
    });
    tracing::info!(target: audit::TARGET, server = AUDIT_SERVER, stage = "register", client_id = %client_id, client_name = client_name.as_deref().unwrap_or("-"), "client registered");
    no_store((StatusCode::CREATED, Json(metadata)).into_response())
}

// ----- authorization endpoint -----

pub async fn authorize(State(s): Server, RawQuery(q): RawQuery) -> Response {
    let p = Params::from_query(q);
    s.store().sweep();

    // Errors before the redirect URI is trusted are shown, never redirected.
    let Some(client_id) = p.get("client_id") else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Missing client_id",
            "The authorization request has no client_id.",
            &[],
            None,
        );
    };
    let Some(client) = s.store().client(client_id) else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Unknown client",
            "This client is not registered with the gateway. MCP clients register automatically; if the gateway was restarted with a fresh state directory, reconnect from the client to register again.",
            &[("client_id", client_id)],
            None,
        );
    };
    let redirect_uri = match p.get("redirect_uri") {
        Some(r) => {
            if !client
                .redirect_uris
                .iter()
                .any(|reg| redirect_uri_matches(reg, r))
            {
                return html::error_page(
                    StatusCode::BAD_REQUEST,
                    "Redirect URI not registered",
                    "The redirect_uri does not match any URI registered for this client.",
                    &[("redirect_uri", r)],
                    None,
                );
            }
            r.to_string()
        }
        None => match client.redirect_uris.as_slice() {
            [only] => only.clone(),
            _ => {
                return html::error_page(
                    StatusCode::BAD_REQUEST,
                    "Missing redirect_uri",
                    "The client registered several redirect URIs, so the request must name one.",
                    &[],
                    None,
                );
            }
        },
    };
    let state = p.get("state").map(str::to_string);
    let fail = |error: &str, desc: &str| {
        redirect(&error_redirect_url(
            &s.issuer,
            &redirect_uri,
            state.as_deref(),
            error,
            desc,
        ))
    };

    if p.get("response_type") != Some("code") {
        return fail("unsupported_response_type", "response_type must be code");
    }
    let Some(code_challenge) = p.get("code_challenge") else {
        return fail(
            "invalid_request",
            "PKCE is required: code_challenge missing",
        );
    };
    if p.get("code_challenge_method") != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    let resources = match s.resolve_resources(&p.all("resource")) {
        Ok(r) => r,
        Err(desc) => return fail("invalid_target", &desc),
    };
    let scopes = s.grant_scopes(&p.scopes(), &resources);

    let provider = match (p.get("provider"), s.providers().len()) {
        (Some(name), _) => match s.providers().get(name) {
            Some(pr) => pr.clone(),
            None => return fail("invalid_request", "unknown provider"),
        },
        (None, 1) => s.providers().values().next().expect("one provider").clone(),
        (None, _) => {
            // Several providers: let the human choose; keep every parameter.
            let base = format!(
                "{AUTHORIZE_PATH}?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(p.0.iter().filter(|(k, _)| k != "provider"))
                    .finish()
            );
            let links: Vec<(String, String)> = s
                .providers()
                .iter()
                .map(|(name, pr)| {
                    (
                        format!("{base}&provider={}", util::urlencode(name)),
                        pr.display_name.clone(),
                    )
                })
                .collect();
            return html::picker_page(&client.display_name(), &links);
        }
    };

    let pending = Pending {
        id: random_token(32),
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        code_challenge: code_challenge.to_string(),
        scopes,
        resources: resources.iter().map(|r| r.resource.clone()).collect(),
        provider: Some(provider.name.clone()),
        upstream_verifier: random_token(48),
        nonce: random_token(16),
        created_at: now(),
        identity: None,
        user: None,
    };
    let upstream_challenge = util::b64url(&util::sha256(pending.upstream_verifier.as_bytes()));
    let url = provider.authorize_url(
        &s.callback_url(),
        &pending.id,
        &pending.nonce,
        &upstream_challenge,
    );
    s.store().insert_pending(pending);
    redirect(url.as_str())
}

// ----- upstream callback -----

pub async fn callback(State(s): Server, RawQuery(q): RawQuery) -> Response {
    let p = Params::from_query(q);
    let Some(txn) = p.get("state") else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Invalid callback",
            "The identity provider's response has no state parameter.",
            &[],
            None,
        );
    };
    let Some(mut pending) = s.store().pending(txn) else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in expired",
            "This sign-in attempt is unknown or has expired (they last ten minutes). Start the connection again from your MCP client.",
            &[],
            None,
        );
    };
    let back = |error: &str, desc: &str| {
        error_redirect_url(
            &s.issuer,
            &pending.redirect_uri,
            pending.state.as_deref(),
            error,
            desc,
        )
    };

    if let Some(err) = p.get("error") {
        s.store().take_pending(txn);
        let desc = p.get("error_description").unwrap_or("");
        audit::authn(
            AUDIT_SERVER,
            "deny",
            None,
            None,
            &format!("provider returned {err}: {desc}"),
        );
        return redirect(&back("access_denied", &format!("identity provider: {err}")));
    }
    let Some(code) = p.get("code") else {
        s.store().take_pending(txn);
        return redirect(&back("server_error", "identity provider returned no code"));
    };
    let provider_name = pending.provider.clone().unwrap_or_default();
    let Some(provider) = s.providers().get(&provider_name).cloned() else {
        s.store().take_pending(txn);
        return redirect(&back("server_error", "provider vanished"));
    };

    let identity = match provider
        .exchange(
            code,
            &s.callback_url(),
            &pending.upstream_verifier,
            &pending.nonce,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            s.store().take_pending(txn);
            tracing::warn!(provider = %provider_name, error = %e, "upstream login failed");
            audit::authn(
                AUDIT_SERVER,
                "deny",
                None,
                None,
                &format!("upstream login failed: {e}"),
            );
            return html::error_page(
                StatusCode::BAD_GATEWAY,
                "Sign-in failed",
                "The identity provider's response could not be verified.",
                &[("detail", &e.to_string())],
                Some((
                    &back("server_error", "upstream login failed"),
                    "Return to application",
                )),
            );
        }
    };

    // Who is this, and may they use what they asked for?
    let user = s
        .policy()
        .resolve_user(&identity.subject, identity.email.as_deref());
    let Some(user) = user else {
        audit::authn(
            AUDIT_SERVER,
            "deny",
            Some(&identity.subject),
            None,
            &format!(
                "identity does not map to a configured user (email {})",
                identity.email.as_deref().unwrap_or("-")
            ),
        );
        s.store().take_pending(txn);
        return html::error_page(
            StatusCode::FORBIDDEN,
            "This account is not allowed",
            "You signed in successfully, but this account is not listed under `users` in the gateway configuration. Add the subject or email below to a user and restart the gateway.",
            &[
                ("subject", &identity.subject),
                ("email", identity.email.as_deref().unwrap_or("(none)")),
            ],
            Some((
                &back("access_denied", "account not permitted"),
                "Return to application",
            )),
        );
    };
    let principal = Principal {
        subject: identity.subject.clone(),
        email: identity.email.clone(),
        user: Some(user.clone()),
        scopes: pending.scopes.clone(),
        claims: Default::default(),
    };
    for server in s.server_names(&pending.resources) {
        if let crate::policy::Decision::Deny { reason } =
            s.policy().authorize_server(&principal, &server)
        {
            audit::authn(
                AUDIT_SERVER,
                "deny",
                Some(&identity.subject),
                Some(&user),
                &format!("not permitted on `{server}`: {reason}"),
            );
            s.store().take_pending(txn);
            return html::error_page(
                StatusCode::FORBIDDEN,
                "Not allowed on this server",
                &format!("User `{user}` may not use the `{server}` server."),
                &[("reason", &reason), ("subject", &identity.subject)],
                Some((
                    &back("access_denied", "not permitted on requested resource"),
                    "Return to application",
                )),
            );
        }
    }
    audit::authn(
        AUDIT_SERVER,
        "login",
        Some(&identity.subject),
        Some(&user),
        &format!(
            "signed in via {provider_name} for client {}",
            pending.client_id
        ),
    );

    pending.identity = Some(identity.clone());
    pending.user = Some(user.clone());
    if s.store().has_consent(&identity.subject, &pending.client_id) {
        return finish(&s, pending);
    }
    s.store().update_pending(pending.clone());
    let client = s.store().client(&pending.client_id);
    let client_name = client
        .as_ref()
        .map(Client::display_name)
        .unwrap_or_else(|| pending.client_id.clone());
    let servers = s.server_names(&pending.resources);
    html::consent_page(&html::ConsentView {
        txn: &pending.id,
        client_name: &client_name,
        client_uri: client.as_ref().and_then(|c| c.client_uri.as_deref()),
        redirect_uri: &pending.redirect_uri,
        servers: &servers,
        scopes: &pending.scopes,
        identity_label: &identity_label(&pending),
        action_url: CONSENT_PATH,
    })
}

pub async fn consent(State(s): Server, body: Bytes) -> Response {
    let p = Params::from_form(&body);
    let Some(txn) = p.get("txn") else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "Missing transaction.",
            &[],
            None,
        );
    };
    let Some(pending) = s.store().pending(txn) else {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in expired",
            "This sign-in attempt is unknown or has expired. Start again from your MCP client.",
            &[],
            None,
        );
    };
    if pending.identity.is_none() || pending.user.is_none() {
        return html::error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "Sign in first.",
            &[],
            None,
        );
    }
    match p.get("action") {
        Some("approve") => {
            let subject = pending
                .identity
                .as_ref()
                .map(|i| i.subject.clone())
                .unwrap_or_default();
            s.store().grant_consent(&subject, &pending.client_id);
            audit::authn(
                AUDIT_SERVER,
                "consent",
                Some(&subject),
                pending.user.as_deref(),
                &format!("approved client {}", pending.client_id),
            );
            finish(&s, pending)
        }
        _ => {
            s.store().take_pending(txn);
            redirect(&error_redirect_url(
                &s.issuer,
                &pending.redirect_uri,
                pending.state.as_deref(),
                "access_denied",
                "the user declined",
            ))
        }
    }
}

/// Issue the authorization code and send the browser back to the client.
fn finish(s: &AuthorizationServer, pending: Pending) -> Response {
    s.store().take_pending(&pending.id);
    let (Some(identity), Some(user)) = (pending.identity.clone(), pending.user.clone()) else {
        return redirect(&error_redirect_url(
            &s.issuer,
            &pending.redirect_uri,
            pending.state.as_deref(),
            "server_error",
            "login state lost",
        ));
    };
    let code = format!("hma_{}", random_token(32));
    s.store().insert_code(
        code.clone(),
        AuthCode {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            scopes: pending.scopes.clone(),
            resources: pending.resources.clone(),
            identity,
            user,
            expires_at: now() + CODE_TTL,
        },
    );
    let mut params = vec![("code", code.as_str()), ("iss", s.issuer.as_str())];
    if let Some(st) = pending.state.as_deref() {
        params.push(("state", st));
    }
    redirect(&with_params(&pending.redirect_uri, &params))
}

// ----- token endpoint -----

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    let dec = |s: &str| {
        url::form_urlencoded::parse(format!("x={s}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| s.to_string())
    };
    Some((dec(id), dec(secret)))
}

pub async fn token(State(s): Server, headers: HeaderMap, body: Bytes) -> Response {
    let p = Params::from_form(&body);
    let basic = basic_credentials(&headers);
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| p.get("client_id").map(str::to_string));
    let Some(client_id) = client_id else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client_id missing",
        );
    };
    let Some(client) = s.store().client(&client_id) else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "unknown client_id (register again if the gateway state was reset)",
        );
    };
    if !client.is_public() {
        let presented = basic
            .as_ref()
            .map(|(_, sec)| sec.clone())
            .or_else(|| p.get("client_secret").map(str::to_string));
        let ok = match (&client.client_secret_hash, presented) {
            (Some(stored), Some(given)) => {
                util::constant_time_eq(hash_secret(&given).as_bytes(), stored.as_bytes())
            }
            _ => false,
        };
        if !ok {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            );
        }
    }
    s.store().touch_client(&client_id);

    match p.get("grant_type") {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (p.get("code"), p.get("code_verifier")) else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required",
                );
            };
            let Some(auth) = s.store().consume_code(code) else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "authorization code is unknown, used or expired",
                );
            };
            if auth.client_id != client_id {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "code was issued to another client",
                );
            }
            if let Some(r) = p.get("redirect_uri")
                && r != auth.redirect_uri
            {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "redirect_uri mismatch",
                );
            }
            if !util::pkce_s256_matches(verifier, &auth.code_challenge) {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                );
            }
            let resources = match narrow_resources(&s, &p.all("resource"), &auth.resources) {
                Ok(r) => r,
                Err(desc) => return json_error(StatusCode::BAD_REQUEST, "invalid_target", &desc),
            };
            let grant = Grant {
                client_id: &client_id,
                identity: &auth.identity,
                user: &auth.user,
                scopes: &auth.scopes,
                resources: &resources,
            };
            let refresh = s.issue_refresh_token(&grant, None);
            audit::authn(
                AUDIT_SERVER,
                "token",
                Some(&auth.identity.subject),
                Some(&auth.user),
                &format!(
                    "authorization_code for client {client_id} aud {}",
                    resources.join(",")
                ),
            );
            token_response(&s, &grant, &refresh)
        }
        Some("refresh_token") => {
            let Some(rt) = p.get("refresh_token") else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            let Some(stored) = s.store().consume_refresh(&hash_secret(rt)) else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh token is unknown, rotated or expired",
                );
            };
            if stored.client_id != client_id {
                // Token presented by the wrong client: treat as compromise.
                let n = s
                    .store()
                    .revoke_refresh_for(&stored.client_id, &stored.identity.subject);
                tracing::warn!(
                    revoked = n,
                    "refresh token presented by a different client; revoked the family"
                );
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh token was issued to another client",
                );
            }
            // The identity may have been removed from `users` since login.
            if s.policy()
                .resolve_user(&stored.identity.subject, stored.identity.email.as_deref())
                .as_deref()
                != Some(stored.user.as_str())
            {
                audit::authn(
                    AUDIT_SERVER,
                    "deny",
                    Some(&stored.identity.subject),
                    Some(&stored.user),
                    "refresh denied: identity no longer maps to that user",
                );
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "identity is no longer permitted",
                );
            }
            let resources = match narrow_resources(&s, &p.all("resource"), &stored.resources) {
                Ok(r) => r,
                Err(desc) => return json_error(StatusCode::BAD_REQUEST, "invalid_target", &desc),
            };
            let requested = p.scopes();
            let scopes: Vec<String> = if requested.is_empty() {
                stored.scopes.clone()
            } else {
                if requested.iter().any(|r| !stored.scopes.contains(r)) {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "cannot widen scope on refresh",
                    );
                }
                requested
            };
            let grant = Grant {
                client_id: &client_id,
                identity: &stored.identity,
                user: &stored.user,
                scopes: &scopes,
                resources: &resources,
            };
            let refresh = s.issue_refresh_token(&grant, Some(stored.expires_at));
            audit::authn(
                AUDIT_SERVER,
                "token",
                Some(&stored.identity.subject),
                Some(&stored.user),
                &format!("refresh for client {client_id}"),
            );
            token_response(&s, &grant, &refresh)
        }
        Some(other) => json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("grant_type `{other}` is not supported"),
        ),
        None => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "grant_type is required",
        ),
    }
}

/// `resource` at the token endpoint may only narrow what was authorized.
fn narrow_resources(
    s: &AuthorizationServer,
    requested: &[String],
    authorized: &[String],
) -> Result<Vec<String>, String> {
    if requested.is_empty() {
        return Ok(authorized.to_vec());
    }
    let resolved = s.resolve_resources(requested)?;
    let mut out = Vec::new();
    for r in resolved {
        if !authorized.contains(&r.resource) {
            return Err(format!(
                "`{}` was not part of the authorization",
                r.resource
            ));
        }
        out.push(r.resource);
    }
    Ok(out)
}

fn token_response(s: &AuthorizationServer, grant: &Grant<'_>, refresh: &str) -> Response {
    match s.mint_access_token(grant) {
        Ok((access_token, expires_in)) => {
            let mut body = json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": refresh,
            });
            if !grant.scopes.is_empty() {
                body["scope"] = Value::String(grant.scopes.join(" "));
            }
            no_store(Json(body).into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "token signing failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token signing failed",
            )
        }
    }
}
