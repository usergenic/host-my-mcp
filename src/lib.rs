//! host-my-mcp: one public Streamable HTTP MCP gateway in front of many local
//! stdio MCP servers, with OAuth resource-server authentication (Auth0) and
//! per-server / per-tool authorization.
//!
//! Module layout mirrors the responsibilities called out in the design note:
//!
//! - [`config`]   — YAML configuration, env-var substitution, validation
//! - [`auth`]     — protected-resource metadata, JWKS, token validation, principal
//! - [`policy`]   — authorization decisions (identity, server, tool, glob rules)
//! - [`backend`]  — stdio child-process supervision and the rmcp client side
//! - [`bridge`]   — the rmcp `ServerHandler` that proxies one HTTP session to a backend
//! - [`http`]     — axum router: per-path MCP endpoints, well-known metadata, health
//! - [`audit`]    — structured audit logging helpers

pub mod audit;
pub mod auth;
pub mod backend;
pub mod bridge;
pub mod config;
pub mod http;
pub mod policy;

pub use config::Config;
pub use http::{App, build_app};
