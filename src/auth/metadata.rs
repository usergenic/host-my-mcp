//! RFC 9728 Protected Resource Metadata and the `WWW-Authenticate` challenge.

use serde::Serialize;
use url::Url;

use crate::config::{Auth, Config, Server};

#[derive(Debug, Clone, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
}

impl ProtectedResourceMetadata {
    pub fn for_server(cfg: &Config, name: &str, server: &Server) -> Self {
        let auth: &Auth = &cfg.auth;
        Self {
            resource: server.resource().as_str().trim_end_matches('/').to_string(),
            authorization_servers: cfg.authorization_server().into_iter().collect(),
            scopes_supported: server.advertised_scopes(auth).to_vec(),
            bearer_methods_supported: vec!["header".into()],
            resource_name: Some(format!("{name} (host-my-mcp)")),
            resource_documentation: None,
        }
    }
}

/// `https://<public>/.well-known/oauth-protected-resource<path>` per RFC 9728 §3
/// path insertion.
pub fn metadata_url(public_origin: &str, path: &str) -> Url {
    Url::parse(&format!(
        "{public_origin}/.well-known/oauth-protected-resource{path}"
    ))
    .expect("validated origin and path")
}

/// Build a `WWW-Authenticate: Bearer ...` value.
///
/// * no token: `Bearer resource_metadata="...", scope="..."`
/// * bad token: adds `error="invalid_token", error_description="..."`
/// * insufficient scope: `error="insufficient_scope"`
pub fn challenge_header(
    metadata_url: &Url,
    scopes: &[String],
    error: Option<(&str, &str)>,
) -> String {
    let mut parts = vec![format!("resource_metadata=\"{metadata_url}\"")];
    if let Some((code, desc)) = error {
        parts.push(format!("error=\"{code}\""));
        if !desc.is_empty() {
            parts.push(format!("error_description=\"{}\"", quote(desc)));
        }
    }
    if !scopes.is_empty() {
        parts.push(format!("scope=\"{}\"", quote(&scopes.join(" "))));
    }
    format!("Bearer {}", parts.join(", "))
}

fn quote(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_url_inserts_path() {
        let u = metadata_url("https://mcp.example.com", "/omg");
        assert_eq!(
            u.as_str(),
            "https://mcp.example.com/.well-known/oauth-protected-resource/omg"
        );
    }

    #[test]
    fn challenge_formats() {
        let u = metadata_url("https://mcp.example.com", "/omg");
        assert_eq!(
            challenge_header(&u, &[], None),
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/omg\""
        );
        let h = challenge_header(
            &u,
            &["a".into(), "b".into()],
            Some(("invalid_token", "expired \"now\"")),
        );
        assert!(h.contains("error=\"invalid_token\""));
        assert!(h.contains("error_description=\"expired \\\"now\\\"\""));
        assert!(h.ends_with("scope=\"a b\""));
    }
}
