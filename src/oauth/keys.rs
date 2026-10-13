//! The authorization server's token-signing key: an Ed25519 key pair stored
//! as PKCS#8 under the state directory, published as a JWKS, and used both to
//! sign access tokens and (in-process) to validate them.

use std::{path::Path, sync::Arc};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::{Value, json};

use super::util::{b64url, sha256};
use crate::auth::jwks::{JwksError, KeySource};

pub const KEY_FILE: &str = "signing-key.pkcs8";

pub struct Signer {
    encoding: EncodingKey,
    decoding: Arc<DecodingKey>,
    kid: String,
    public_raw: Vec<u8>,
}

impl Signer {
    /// Load `<dir>/signing-key.pkcs8`, generating it (mode 0600) if absent.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("cannot create state_dir {}: {e}", dir.display()))?;
        let path = dir.join(KEY_FILE);
        match std::fs::read(&path) {
            Ok(der) => {
                let signer = Self::from_pkcs8(&der).map_err(|e| {
                    anyhow::anyhow!("{} is not a usable Ed25519 PKCS#8 key: {e}", path.display())
                })?;
                tracing::info!(path = %path.display(), kid = %signer.kid, "loaded token signing key");
                Ok(Arc::new(signer))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let pair = Ed25519KeyPair::generate()
                    .map_err(|_| anyhow::anyhow!("Ed25519 key generation failed"))?;
                let der = pair
                    .to_pkcs8v1()
                    .map_err(|_| anyhow::anyhow!("PKCS#8 encoding failed"))?;
                write_private(&path, der.as_ref())?;
                let signer = Self::from_pkcs8(der.as_ref())?;
                tracing::info!(path = %path.display(), kid = %signer.kid, "generated new token signing key");
                Ok(Arc::new(signer))
            }
            Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
        }
    }

    /// An ephemeral key (tests, or `state_dir` deliberately unset).
    pub fn ephemeral() -> anyhow::Result<Arc<Self>> {
        let pair = Ed25519KeyPair::generate()
            .map_err(|_| anyhow::anyhow!("Ed25519 key generation failed"))?;
        let der = pair
            .to_pkcs8v1()
            .map_err(|_| anyhow::anyhow!("PKCS#8 encoding failed"))?;
        Ok(Arc::new(Self::from_pkcs8(der.as_ref())?))
    }

    pub fn from_pkcs8(der: &[u8]) -> anyhow::Result<Self> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|e| anyhow::anyhow!("invalid PKCS#8: {e}"))?;
        let public_raw = pair.public_key().as_ref().to_vec();
        // RFC 7638-style stable identifier, shortened: tokens carry it as `kid`.
        let kid = b64url(&sha256(&public_raw))[..16].to_string();
        Ok(Self {
            encoding: EncodingKey::from_ed_der(der),
            decoding: Arc::new(DecodingKey::from_ed_der(&public_raw)),
            kid,
            public_raw,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    /// The JWKS document for `/oauth/jwks`.
    pub fn jwks(&self) -> Value {
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64url(&self.public_raw),
                "kid": self.kid,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
    }

    /// Sign `claims` as an RFC 9068-style JWT access token.
    pub fn sign(&self, claims: &Value) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some("at+jwt".into());
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| anyhow::anyhow!("token signing failed: {e}"))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[async_trait::async_trait]
impl KeySource for Signer {
    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        if kid == self.kid {
            Ok(self.decoding.clone())
        } else {
            Err(JwksError::UnknownKid(kid.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Validation, decode};

    #[test]
    fn sign_verify_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let a = Signer::load_or_create(dir.path()).unwrap();
        let b = Signer::load_or_create(dir.path()).unwrap();
        assert_eq!(a.kid(), b.kid(), "second load reuses the stored key");

        let now = jsonwebtoken::get_current_timestamp();
        let tok = a
            .sign(&json!({"iss": "x", "sub": "s", "aud": "r", "exp": now + 60}))
            .unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_audience(&["r"]);
        v.set_issuer(&["x"]);
        let data = decode::<Value>(&tok, &b.decoding, &v).unwrap();
        assert_eq!(data.header.kid.as_deref(), Some(a.kid()));
        assert_eq!(data.claims["sub"], "s");

        // JWKS → DecodingKey round trip (what an external validator would do).
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(a.jwks()).unwrap();
        let jwk = set.find(a.kid()).unwrap();
        let key = DecodingKey::from_jwk(jwk).unwrap();
        decode::<Value>(&tok, &key, &v).unwrap();
    }
}
