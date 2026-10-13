//! Bearer token validation. A token is accepted only if its signature
//! verifies against the issuer's JWKS, `iss` matches, `exp`/`nbf` hold, and
//! `aud` contains the exact resource being accessed (RFC 8707 binding).

use std::{sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use super::jwks::{JwksError, KeySource};
use crate::{config::Auth, policy::Principal};

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("token header has no kid")]
    MissingKid,
    #[error("unsupported algorithm {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("signature or claim validation failed: {0}")]
    Invalid(String),
    #[error("token audience does not include resource `{0}`")]
    WrongAudience(String),
    #[error("token has no `sub` claim")]
    MissingSubject,
    #[error("signing keys unavailable: {0}")]
    Keys(#[from] JwksError),
}

impl TokenError {
    /// `true` when the failure is the gateway's problem (keys unreachable),
    /// not the client's. Such failures surface as 503, not 401, so clients
    /// do not loop through re-authorization.
    pub fn is_server_side(&self) -> bool {
        matches!(
            self,
            TokenError::Keys(JwksError::Fetch(_)) | TokenError::Keys(JwksError::Invalid(_))
        )
    }
}

pub struct TokenValidator {
    keys: Arc<dyn KeySource>,
    issuer: String,
    algorithms: Vec<Algorithm>,
    leeway: Duration,
    email_claim: String,
}

impl TokenValidator {
    /// Validator for an external authorization server (`auth.issuer`).
    pub fn new(auth: &Auth, keys: Arc<dyn KeySource>) -> anyhow::Result<Self> {
        let issuer = auth
            .issuer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("auth.issuer is required"))?
            .as_str()
            .to_string();
        let algorithms = auth
            .algorithms
            .iter()
            .map(|a| {
                a.parse::<Algorithm>()
                    .map_err(|e| anyhow::anyhow!("bad algorithm {a}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::with_issuer(issuer, algorithms, auth, keys))
    }

    /// Validator for an explicit issuer and algorithm list (the built-in
    /// authorization server validates its own tokens this way).
    pub fn with_issuer(
        issuer: String,
        algorithms: Vec<Algorithm>,
        auth: &Auth,
        keys: Arc<dyn KeySource>,
    ) -> Self {
        Self {
            keys,
            issuer,
            algorithms,
            leeway: Duration::from_secs(auth.leeway_secs),
            email_claim: auth.email_claim.clone(),
        }
    }

    /// Validate `token` for `resource` and build a [`Principal`] (without the
    /// `user` field, which the policy layer resolves).
    pub async fn validate(&self, token: &str, resource: &Url) -> Result<Principal, TokenError> {
        let header = decode_header(token).map_err(|e| TokenError::Malformed(e.to_string()))?;
        if !self.algorithms.contains(&header.alg) {
            return Err(TokenError::UnsupportedAlgorithm(header.alg));
        }
        let kid = header.kid.ok_or(TokenError::MissingKid)?;
        let key = self.keys.key_for(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = self.algorithms.clone();
        validation.leeway = self.leeway.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Issuer: Auth0 issuers carry a trailing slash; accept both spellings.
        validation.set_issuer(&[self.issuer.as_str(), self.issuer.trim_end_matches('/')]);
        // Audience is checked by hand below so we can normalize trailing slashes.
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);

        let data = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| TokenError::Invalid(e.to_string()))?;
        let claims = data.claims;

        if !audience_matches(claims.get("aud"), resource) {
            return Err(TokenError::WrongAudience(
                resource.as_str().trim_end_matches('/').to_string(),
            ));
        }

        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(TokenError::MissingSubject)?
            .to_string();
        let email = claims
            .get(&self.email_claim)
            .and_then(Value::as_str)
            .map(str::to_string);
        let scopes = extract_scopes(&claims);

        Ok(Principal {
            subject,
            email,
            user: None,
            scopes,
            claims,
        })
    }
}

fn normalize_resource(s: &str) -> String {
    let mut s = s.trim().trim_end_matches('/').to_string();
    // Scheme and host are case-insensitive; compare them lowercased.
    if let Ok(u) = Url::parse(&s) {
        let lower_prefix =
            format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")).to_lowercase();
        let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
        s = format!("{lower_prefix}{port}{}", u.path().trim_end_matches('/'));
    }
    s
}

/// `aud` may be a string or an array of strings. Exactly one entry must equal
/// the resource (modulo trailing slash and scheme/host case).
pub fn audience_matches(aud: Option<&Value>, resource: &Url) -> bool {
    let want = normalize_resource(resource.as_str());
    match aud {
        Some(Value::String(s)) => normalize_resource(s) == want,
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .any(|s| normalize_resource(s) == want),
        _ => false,
    }
}

/// Merge the OAuth `scope` claim (space-separated) with Auth0's RBAC
/// `permissions` array claim.
pub fn extract_scopes(claims: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(Value::String(s)) = claims.get("scope") {
        out.extend(s.split_whitespace().map(str::to_string));
    }
    if let Some(Value::Array(p)) = claims.get("permissions") {
        out.extend(p.iter().filter_map(Value::as_str).map(str::to_string));
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::jwks::StaticKeys;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    pub const PRIVATE_PEM: &str = include_str!("../../tests/fixtures/test_rsa.pem");
    pub const JWKS: &str = include_str!("../../tests/fixtures/jwks.json");

    pub fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    pub fn sign(claims: serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        header.typ = Some("at+jwt".into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    pub fn auth_cfg() -> Auth {
        Auth {
            issuer: Some("https://tenant.us.auth0.com/".parse().unwrap()),
            email_claim: "https://host-my-mcp/email".into(),
            ..Auth::default()
        }
    }

    pub fn validator() -> TokenValidator {
        TokenValidator::new(&auth_cfg(), StaticKeys::from_json(JWKS).unwrap()).unwrap()
    }

    pub fn good_claims(resource: &str) -> serde_json::Value {
        json!({
            "iss": "https://tenant.us.auth0.com/",
            "sub": "google-oauth2|123",
            "aud": [resource, "https://tenant.us.auth0.com/userinfo"],
            "exp": now() + 300,
            "iat": now(),
            "scope": "openid profile read:x",
            "permissions": ["tool:echo"],
            "https://host-my-mcp/email": "brendan@example.com",
        })
    }

    #[tokio::test]
    async fn accepts_valid_token_for_resource() {
        let v = validator();
        let res: Url = "https://mcp.example.com/echo".parse().unwrap();
        let tok = sign(good_claims("https://mcp.example.com/echo"), "test-key-1");
        let p = v.validate(&tok, &res).await.unwrap();
        assert_eq!(p.subject, "google-oauth2|123");
        assert_eq!(p.email.as_deref(), Some("brendan@example.com"));
        assert!(p.scopes.contains(&"tool:echo".to_string()));
        assert!(p.scopes.contains(&"read:x".to_string()));
    }

    #[tokio::test]
    async fn rejects_wrong_resource_expired_issuer_and_kid() {
        let v = validator();
        let res: Url = "https://mcp.example.com/echo".parse().unwrap();

        let other = sign(good_claims("https://mcp.example.com/toggl"), "test-key-1");
        assert!(matches!(
            v.validate(&other, &res).await,
            Err(TokenError::WrongAudience(_))
        ));

        let mut c = good_claims("https://mcp.example.com/echo");
        c["exp"] = json!(now() - 600);
        assert!(matches!(
            v.validate(&sign(c, "test-key-1"), &res).await,
            Err(TokenError::Invalid(_))
        ));

        let mut c = good_claims("https://mcp.example.com/echo");
        c["iss"] = json!("https://evil.example.com/");
        assert!(matches!(
            v.validate(&sign(c, "test-key-1"), &res).await,
            Err(TokenError::Invalid(_))
        ));

        let unknown = sign(good_claims("https://mcp.example.com/echo"), "nope");
        assert!(matches!(
            v.validate(&unknown, &res).await,
            Err(TokenError::Keys(JwksError::UnknownKid(_)))
        ));

        assert!(matches!(
            v.validate("not.a.jwt", &res).await,
            Err(TokenError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn rejects_hs256_even_with_matching_claims() {
        let v = validator();
        let res: Url = "https://mcp.example.com/echo".parse().unwrap();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".into());
        let tok = encode(
            &header,
            &good_claims("https://mcp.example.com/echo"),
            &EncodingKey::from_secret(b"x"),
        )
        .unwrap();
        assert!(matches!(
            v.validate(&tok, &res).await,
            Err(TokenError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn audience_normalization() {
        let r: Url = "https://MCP.example.com/echo".parse().unwrap();
        assert!(audience_matches(
            Some(&json!("https://mcp.example.com/echo/")),
            &r
        ));
        assert!(audience_matches(
            Some(&json!(["x", "https://mcp.example.com/echo"])),
            &r
        ));
        assert!(!audience_matches(
            Some(&json!("https://mcp.example.com/echo2")),
            &r
        ));
        assert!(!audience_matches(
            Some(&json!("https://mcp.example.com")),
            &r
        ));
        assert!(!audience_matches(None, &r));
    }
}
