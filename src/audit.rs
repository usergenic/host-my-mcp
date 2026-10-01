//! Audit logging. Every authorization decision and every forwarded MCP request
//! produces exactly one `audit` event with enough fields to explain it.
//!
//! Access tokens are never logged. Tool arguments are only logged when
//! `logging.log_arguments: true` is set in the configuration.

use std::time::Duration;

use crate::policy::Decision;

/// The audit `tracing` target. Filter with `RUST_LOG=audit=info`.
pub const TARGET: &str = "audit";

/// Emit one audit line for an MCP request that passed through the gateway.
#[allow(clippy::too_many_arguments)]
pub fn request(
    server: &str,
    subject: Option<&str>,
    user: Option<&str>,
    method: &str,
    tool: Option<&str>,
    decision: &Decision,
    latency: Option<Duration>,
    error: Option<&str>,
    arguments: Option<&serde_json::Value>,
) {
    let (result, reason) = match decision {
        Decision::Allow { reason } => ("allow", reason.as_str()),
        Decision::Deny { reason } => ("deny", reason.as_str()),
    };
    let latency_ms = latency.map(|d| d.as_millis() as u64);
    match arguments {
        Some(args) => tracing::info!(
            target: TARGET,
            server,
            subject = subject.unwrap_or("-"),
            user = user.unwrap_or("-"),
            method,
            tool = tool.unwrap_or("-"),
            result,
            reason,
            latency_ms,
            error,
            arguments = %args,
        ),
        None => tracing::info!(
            target: TARGET,
            server,
            subject = subject.unwrap_or("-"),
            user = user.unwrap_or("-"),
            method,
            tool = tool.unwrap_or("-"),
            result,
            reason,
            latency_ms,
            error,
        ),
    }
}

/// Emit one audit line for an HTTP-level authentication outcome.
pub fn authn(server: &str, outcome: &str, subject: Option<&str>, user: Option<&str>, detail: &str) {
    tracing::info!(
        target: TARGET,
        server,
        stage = "authn",
        outcome,
        subject = subject.unwrap_or("-"),
        user = user.unwrap_or("-"),
        detail,
    );
}
