//! OAuth 2.1 resource-server behaviour: protected-resource metadata (RFC 9728),
//! bearer-token validation against the issuer's JWKS, principal extraction,
//! and the axum middleware that guards each MCP mount.
//!
//! The gateway never performs login, code exchange, or token issuance; Auth0
//! owns that. This module only answers "is this bearer token valid for this
//! resource, and who is it?" and fails closed on any doubt.

pub mod jwks;
pub mod metadata;
pub mod middleware;
pub mod token;

pub use jwks::JwksCache;
pub use metadata::{ProtectedResourceMetadata, challenge_header};
pub use middleware::{AuthLayerState, require_auth};
pub use token::{TokenError, TokenValidator};
