#![allow(deprecated)] // logging notifications are legacy but still forwarded

//! The rmcp `ClientHandler` the gateway presents to each backend process.
//! It fans server-initiated notifications out to gateway sessions.

use std::sync::Arc;

use rmcp::{
    ClientHandler, RoleClient,
    model::{
        ClientCapabilities, ClientConfig, Implementation, LoggingMessageNotificationParam,
        ProgressNotificationParam, ProtocolVersion, ResourceUpdatedNotificationParam,
    },
    service::NotificationContext,
};

use crate::bridge::registry::SessionRegistry;

#[derive(Clone)]
pub struct BackendClient {
    name: String,
    registry: Arc<SessionRegistry>,
}

impl BackendClient {
    pub fn new(name: String, registry: Arc<SessionRegistry>) -> Self {
        Self { name, registry }
    }
}

macro_rules! fan_out {
    ($self:ident, $what:literal, |$peer:ident| $send:expr) => {{
        let peers = $self.registry.peers();
        tracing::debug!(backend = %$self.name, sessions = peers.len(), concat!("forwarding ", $what));
        for $peer in peers {
            if let Err(e) = $send.await {
                tracing::debug!(backend = %$self.name, error = %e, concat!("failed to forward ", $what));
            }
        }
    }};
}

impl ClientHandler for BackendClient {
    fn get_info(&self) -> ClientConfig {
        let mut cfg = ClientConfig::default();
        cfg.protocol_version = ProtocolVersion::LATEST_WITH_INITIALIZE;
        cfg.capabilities = ClientCapabilities::default();
        cfg.client_info = Implementation::new("host-my-mcp", env!("CARGO_PKG_VERSION"))
            .with_title(format!("host-my-mcp gateway ({})", self.name))
            .with_website_url("https://github.com/usergenic/host-my-mcp");
        cfg
    }

    async fn on_progress(&self, params: ProgressNotificationParam, _ctx: NotificationContext<RoleClient>) {
        match self.registry.route_progress(&params.progress_token) {
            Some(route) => {
                let mut forwarded = ProgressNotificationParam::new(route.client_token, params.progress);
                forwarded.total = params.total;
                forwarded.message = params.message;
                forwarded.meta = params.meta;
                if let Err(e) = route.peer.notify_progress(forwarded).await {
                    tracing::debug!(backend = %self.name, error = %e, "failed to forward progress");
                }
            }
            None => tracing::trace!(backend = %self.name, "progress for unknown token dropped"),
        }
    }

    async fn on_tool_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        fan_out!(self, "tools/list_changed", |peer| peer.notify_tool_list_changed());
    }

    async fn on_prompt_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        fan_out!(self, "prompts/list_changed", |peer| peer.notify_prompt_list_changed());
    }

    async fn on_resource_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        fan_out!(self, "resources/list_changed", |peer| peer.notify_resource_list_changed());
    }

    async fn on_resource_updated(&self, params: ResourceUpdatedNotificationParam, _ctx: NotificationContext<RoleClient>) {
        fan_out!(self, "resources/updated", |peer| peer.notify_resource_updated(params.clone()));
    }

    #[allow(deprecated)]
    async fn on_logging_message(&self, params: LoggingMessageNotificationParam, _ctx: NotificationContext<RoleClient>) {
        fan_out!(self, "logging message", |peer| peer.notify_logging_message(params.clone()));
    }
}
