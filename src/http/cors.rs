//! CORS for browser-based MCP clients.
//!
//! The allowlist is `listen.allowed_origins`, the same list rmcp uses to
//! validate the `Origin` header, so the two can never disagree: an origin that
//! passes validation gets CORS headers, every other origin gets none (and, if
//! validation is on, the transport's 403). Entries use rmcp's grammar,
//! `scheme://host`, `scheme://host:port` or `scheme://host:*` (any port);
//! `*` and `null` are rejected in config validation because the gateway is a
//! bearer-token API.
//!
//! Browsers never send `Authorization` on a preflight, so this middleware sits
//! *outside* the auth layer and answers `OPTIONS` itself with 204. Actual
//! responses, including the 401 challenge and the RFC 9728 metadata, get
//! `Access-Control-Allow-Origin`, `Vary: Origin` and an
//! `Access-Control-Expose-Headers` list so the browser can read
//! `WWW-Authenticate` and the MCP session headers.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub const ALLOW_METHODS: &str = "GET, POST, DELETE, OPTIONS";
pub const ALLOW_HEADERS: &str =
    "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID";
pub const EXPOSE_HEADERS: &str = "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version";
pub const MAX_AGE: &str = "600";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Port {
    /// `:*`
    Any,
    /// No port given; matches any port (mirrors rmcp's current behaviour).
    Unspecified,
    Exact(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedOrigin {
    scheme: String,
    host: String,
    port: Port,
}

/// Parsed `listen.allowed_origins`.
#[derive(Debug, Clone, Default)]
pub struct OriginAllowlist {
    entries: Vec<AllowedOrigin>,
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

/// Parse a serialized origin (`scheme://host[:port]`) into its tuple.
fn parse_origin(value: &str) -> Option<(String, String, Option<u16>)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let uri = http::Uri::try_from(value).ok()?;
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return None;
    }
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;
    Some((
        scheme,
        normalize_host(authority.host()),
        authority.port_u16(),
    ))
}

impl OriginAllowlist {
    /// Parse config entries; the error names the offending entry and why.
    pub fn parse(raw: &[String]) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(raw.len());
        for value in raw {
            let v = value.trim();
            if v == "*" {
                return Err("`*` is not accepted: the gateway is a bearer-token API, so CORS must name the exact browser origins (e.g. `http://localhost:5173`, or `http://localhost:*` for any port)".into());
            }
            if v.eq_ignore_ascii_case("null") {
                return Err("`null` is not accepted: opaque origins cannot be granted CORS".into());
            }
            let entry = if let Some(base) = v.strip_suffix(":*") {
                match parse_origin(base) {
                    Some((scheme, host, None)) => AllowedOrigin {
                        scheme,
                        host,
                        port: Port::Any,
                    },
                    _ => {
                        return Err(format!(
                            "`{value}` is not a valid origin pattern (expected `scheme://host:*`)"
                        ));
                    }
                }
            } else {
                match parse_origin(v) {
                    Some((scheme, host, port)) => AllowedOrigin {
                        scheme,
                        host,
                        port: port.map_or(Port::Unspecified, Port::Exact),
                    },
                    None => {
                        return Err(format!(
                            "`{value}` is not a valid origin (expected `scheme://host`, `scheme://host:port` or `scheme://host:*`)"
                        ));
                    }
                }
            };
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does this `Origin` header value match an entry?
    pub fn matches(&self, origin: &str) -> bool {
        let Some((scheme, host, port)) = parse_origin(origin) else {
            return false;
        };
        self.entries.iter().any(|a| {
            a.scheme == scheme
                && a.host == host
                && match a.port {
                    Port::Any | Port::Unspecified => true,
                    Port::Exact(p) => port.or_else(|| default_port(&scheme)) == Some(p),
                }
        })
    }

    /// The `Origin` header of `headers`, if present and allowed.
    fn allowed_origin(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        let value = headers.get(header::ORIGIN)?;
        if self.matches(value.to_str().ok()?) {
            Some(value.clone())
        } else {
            None
        }
    }
}

fn append_vary_origin(headers: &mut HeaderMap) {
    let already = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("origin") || v.trim() == "*");
    if !already {
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

/// axum middleware: answer preflights for allowed origins and decorate every
/// other response to an allowed origin with CORS headers. Requests from
/// origins not on the list (or with no `Origin`) pass through untouched.
pub async fn cors(State(allow): State<Arc<OriginAllowlist>>, req: Request, next: Next) -> Response {
    let Some(origin) = allow.allowed_origin(req.headers()) else {
        return next.run(req).await;
    };

    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(ALLOW_METHODS),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(ALLOW_HEADERS),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        append_vary_origin(h);
        return resp;
    }

    let mut resp: Response<Body> = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSE_HEADERS),
    );
    append_vary_origin(h);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> OriginAllowlist {
        OriginAllowlist::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn exact_origins_match_scheme_host_and_port() {
        let l = list(&["http://localhost:5173", "https://app.example.com"]);
        assert!(l.matches("http://localhost:5173"));
        assert!(l.matches("HTTP://LocalHost:5173"));
        assert!(!l.matches("http://localhost:5174"));
        assert!(!l.matches("https://localhost:5173"));
        assert!(l.matches("https://app.example.com"));
        assert!(
            l.matches("https://app.example.com:443"),
            "default port is implied"
        );
        assert!(!l.matches("https://evil.example.com"));
        assert!(!l.matches("null"));
        assert!(!l.matches(""));
    }

    #[test]
    fn port_wildcard_and_portless_entries() {
        let l = list(&["http://localhost:*"]);
        assert!(l.matches("http://localhost:5173"));
        assert!(l.matches("http://localhost"));
        assert!(!l.matches("http://127.0.0.1:5173"));
        let l = list(&["https://app.example.com:8443"]);
        assert!(l.matches("https://app.example.com:8443"));
        assert!(!l.matches("https://app.example.com"));
        let l = list(&["http://[::1]:*"]);
        assert!(l.matches("http://[::1]:3000"));
    }

    #[test]
    fn rejects_wildcard_null_and_garbage() {
        for bad in [
            "*",
            "null",
            "NULL",
            "localhost:5173",
            "http://",
            "https://a.example/path",
            "https://a.example:443:*",
            "",
        ] {
            assert!(
                OriginAllowlist::parse(&[bad.to_string()]).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(OriginAllowlist::parse(&[]).unwrap().is_empty());
    }

    #[test]
    fn vary_origin_is_appended_once() {
        let mut h = HeaderMap::new();
        append_vary_origin(&mut h);
        append_vary_origin(&mut h);
        assert_eq!(h.get_all(header::VARY).iter().count(), 1);
        let mut h = HeaderMap::new();
        h.insert(header::VARY, HeaderValue::from_static("Accept, origin"));
        append_vary_origin(&mut h);
        assert_eq!(h.get_all(header::VARY).iter().count(), 1);
    }
}
