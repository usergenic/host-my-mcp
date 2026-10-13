//! Small helpers shared by the authorization server: time, randomness,
//! base64url, SHA-256, PKCE and constant-time comparison.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `n` random bytes as base64url without padding (so 32 bytes → 43 chars).
pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    aws_lc_rs::rand::fill(&mut buf).expect("system RNG");
    b64url(&buf)
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// Opaque, stable, one-way reference to a secret (client secrets and refresh
/// tokens are stored hashed so the state file never contains a usable secret).
pub fn hash_secret(secret: &str) -> String {
    b64url(&sha256(secret.as_bytes()))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// RFC 7636 `S256`: `BASE64URL(SHA256(verifier)) == challenge`.
pub fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let computed = b64url(&sha256(verifier.as_bytes()));
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Percent-encode for a query string component.
pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Minimal HTML escaping for text and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_roundtrip() {
        let verifier = random_token(32);
        let challenge = b64url(&sha256(verifier.as_bytes()));
        assert!(pkce_s256_matches(&verifier, &challenge));
        assert!(!pkce_s256_matches(&verifier, "nope"));
        assert!(!pkce_s256_matches("short", &challenge));
    }

    #[test]
    fn escaping() {
        assert_eq!(
            html_escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(urlencode("a b&c=d"), "a+b%26c%3Dd");
    }
}
