#![allow(deprecated)] // logging/setLevel and resources/subscribe are legacy but still forwarded

//! The bridge: an rmcp [`ServerHandler`] instantiated once per external MCP
//! session that forwards requests to a backend's client peer, enforcing
//! policy on the way in and translating notifications on the way out.

pub mod registry;

use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResponse, CancelledNotificationParam,
        ClientRequest, CompleteRequest, CompleteRequestParams, CompleteResult, ErrorCode,
        GetPromptRequest, GetPromptRequestParams, GetPromptResponse, Implementation,
        InitializeRequestParams, InitializeResult, ListPromptsResult,
        ListResourceTemplatesResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParams,
        ProtocolVersion, ReadResourceRequest, ReadResourceRequestParams, ReadResourceResponse,
        RequestOptionalParam, ServerResult, SetLevelRequest, SetLevelRequestParams,
        SubscribeRequest, SubscribeRequestParams, UnsubscribeRequest, UnsubscribeRequestParams,
    },
    service::{NotificationContext, PeerRequestOptions, RequestContext, ServiceError},
};

use crate::{
    audit,
    backend::{Backend, BackendError},
    config::{Lifecycle, Server},
    policy::{Authorizer, Decision, Principal, RequestContext as PolicyContext},
};
use registry::{ProgressRoute, SessionRegistry};

/// Everything a handler needs that is shared across sessions of one server.
pub struct ServerContext {
    pub name: String,
    pub config: Server,
    pub policy: Arc<dyn Authorizer>,
    pub auth_disabled: bool,
    pub log_arguments: bool,
    /// The shared backend (for `lifecycle: shared`).
    pub shared_backend: Arc<Backend>,
}

impl ServerContext {
    /// Build a handler for a new session.
    pub fn new_handler(self: &Arc<Self>) -> GatewayHandler {
        let backend = match self.config.lifecycle {
            Lifecycle::Shared => self.shared_backend.clone(),
            Lifecycle::PerSession => {
                let registry = SessionRegistry::new();
                Backend::new(self.shared_backend.spec().clone(), registry)
            }
        };
        GatewayHandler { ctx: self.clone(), backend, session_id: OnceLock::new() }
    }
}

pub struct GatewayHandler {
    ctx: Arc<ServerContext>,
    backend: Arc<Backend>,
    session_id: OnceLock<u64>,
}

impl Drop for GatewayHandler {
    fn drop(&mut self) {
        if let Some(id) = self.session_id.get() {
            self.backend.registry().unregister_session(*id);
            tracing::debug!(server = %self.ctx.name, session = id, "session closed");
        }
        if self.ctx.config.lifecycle == Lifecycle::PerSession {
            self.backend.shutdown();
        }
    }
}

fn backend_error(e: BackendError) -> McpError {
    tracing::error!(error = %e, "backend unavailable");
    McpError::new(ErrorCode::INTERNAL_ERROR, "backend unavailable", None)
}

fn service_error(e: ServiceError) -> McpError {
    match e {
        // The backend answered with a JSON-RPC error: pass it through verbatim.
        ServiceError::McpError(e) => e,
        ServiceError::Timeout { timeout } => {
            McpError::new(ErrorCode::INTERNAL_ERROR, format!("backend did not answer within {}s", timeout.as_secs()), None)
        }
        ServiceError::Cancelled { reason } => McpError::new(
            ErrorCode::INTERNAL_ERROR,
            format!("request cancelled{}", reason.map(|r| format!(": {r}")).unwrap_or_default()),
            None,
        ),
        ServiceError::TransportClosed | ServiceError::TransportSend(_) => {
            McpError::new(ErrorCode::INTERNAL_ERROR, "backend unavailable", None)
        }
        other => {
            tracing::error!(error = %other, "unexpected backend error");
            McpError::new(ErrorCode::INTERNAL_ERROR, "backend error", None)
        }
    }
}

/// Build a request whose params are optional (the `*/list` family).
fn optional_request<M: Default, P>(params: Option<P>) -> RequestOptionalParam<M, P> {
    RequestOptionalParam { method: M::default(), params, extensions: Default::default() }
}

fn cancelled_param(id: rmcp::model::RequestId) -> CancelledNotificationParam {
    CancelledNotificationParam::new(Some(id), Some("client cancelled".into()))
}

fn denied(reason: &str) -> McpError {
    // -32001 is unassigned in MCP; carry a stable application code for clients.
    McpError::new(ErrorCode(-32001), format!("forbidden: {reason}"), None)
}

macro_rules! expect_variant {
    ($res:expr, $( $variant:ident => $map:expr ),+ $(,)?) => {
        match $res {
            $( ServerResult::$variant(r) => Ok($map(r)), )+
            other => {
                tracing::error!(?other, "unexpected result type from backend");
                Err(McpError::new(ErrorCode::INTERNAL_ERROR, "unexpected result type from backend", None))
            }
        }
    };
}

impl GatewayHandler {
    fn principal(&self, extensions: &rmcp::model::Extensions) -> Result<Principal, McpError> {
        let found = extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Principal>())
            .cloned();
        match found {
            Some(p) => Ok(p),
            None if self.ctx.auth_disabled => Ok(Principal::anonymous()),
            None => {
                tracing::error!(server = %self.ctx.name, "request reached handler without a principal; failing closed");
                Err(McpError::new(ErrorCode::INTERNAL_ERROR, "authentication context missing", None))
            }
        }
    }

    fn ensure_registered(&self, peer: &rmcp::service::Peer<RoleServer>) {
        self.session_id.get_or_init(|| {
            let id = self.backend.registry().register_session(peer.clone());
            tracing::debug!(server = %self.ctx.name, session = id, "session opened");
            id
        });
    }

    fn authorize(&self, principal: &Principal, method: &str, tool: Option<&str>, args: Option<&rmcp::model::JsonObject>) -> Decision {
        self.ctx.policy.authorize(&PolicyContext {
            principal,
            server: &self.ctx.name,
            method,
            tool,
            arguments: args,
        })
    }

    /// Authorize a non-tool method, forward `request` to the backend, audit.
    async fn forward<R, F>(
        &self,
        context: &RequestContext<RoleServer>,
        method: &str,
        request: rmcp::model::ClientRequest,
        map: F,
    ) -> Result<R, McpError>
    where
        F: FnOnce(ServerResult) -> Result<R, McpError>,
    {
        self.ensure_registered(&context.peer);
        let principal = self.principal(&context.extensions)?;
        let decision = self.authorize(&principal, method, None, None);
        if !decision.is_allowed() {
            audit::request(&self.ctx.name, Some(&principal.subject), principal.user.as_deref(), method, None, &decision, None, None, None);
            return Err(denied(decision.reason()));
        }
        let started = Instant::now();
        let result = async {
            let peer = self.backend.peer().await.map_err(backend_error)?;
            let handle = peer
                .send_request_with_option(
                    request,
                    PeerRequestOptions::with_timeout(self.backend.spec().request_timeout).reset_timeout_on_progress(),
                )
                .await
                .map_err(service_error)?;
            let id = handle.id.clone();
            let bpeer = handle.peer.clone();
            tokio::select! {
                r = handle.await_response() => r.map_err(service_error),
                _ = context.ct.cancelled() => {
                    let _ = bpeer.notify_cancelled(cancelled_param(id)).await;
                    Err(McpError::new(ErrorCode::INTERNAL_ERROR, "request cancelled", None))
                }
            }
        }
        .await;
        let err_text = result.as_ref().err().map(|e| e.message.to_string());
        audit::request(
            &self.ctx.name,
            Some(&principal.subject),
            principal.user.as_deref(),
            method,
            None,
            &decision,
            Some(started.elapsed()),
            err_text.as_deref(),
            None,
        );
        map(result?)
    }
}

impl ServerHandler for GatewayHandler {
    fn get_info(&self) -> InitializeResult {
        // Only used before the backend has been consulted (e.g. discovery);
        // `initialize` below replaces it with the backend's real capabilities.
        InitializeResult::new(Default::default())
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
            .with_server_info(
                Implementation::new(format!("host-my-mcp/{}", self.ctx.name), env!("CARGO_PKG_VERSION"))
                    .with_title(format!("{} via host-my-mcp", self.ctx.name)),
            )
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        // Sessions are required for correct per-session notification routing;
        // 2026-07-28 removes them, so we cap negotiation at the last version
        // with an `initialize` handshake.
        std::borrow::Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::LATEST_WITH_INITIALIZE))
    }

    async fn initialize(&self, request: InitializeRequestParams, context: RequestContext<RoleServer>) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        self.ensure_registered(&context.peer);
        let principal = self.principal(&context.extensions)?;
        let decision = self.authorize(&principal, "initialize", None, None);
        if !decision.is_allowed() {
            audit::request(&self.ctx.name, Some(&principal.subject), principal.user.as_deref(), "initialize", None, &decision, None, None, None);
            return Err(denied(decision.reason()));
        }
        let started = Instant::now();
        let negotiated = self.negotiate_initialize(&request)?;
        let info = self.backend.info().await.map_err(backend_error)?;
        audit::request(&self.ctx.name, Some(&principal.subject), principal.user.as_deref(), "initialize", None, &decision, Some(started.elapsed()), None, None);

        let mut backend_impl = info.server_info.clone().unwrap_or_else(|| Implementation::new(self.ctx.name.clone(), "unknown"));
        backend_impl.title = Some(format!("{} via host-my-mcp", backend_impl.title.clone().unwrap_or_else(|| backend_impl.name.clone())));
        let mut result = InitializeResult::new(info.capabilities.clone())
            .with_protocol_version(negotiated.protocol_version)
            .with_server_info(backend_impl);
        result.instructions = info.instructions.clone();
        Ok(result)
    }

    async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        let principal = self.principal(&context.extensions)?;
        let mut result = self
            .forward(&context, "tools/list", ClientRequest::ListToolsRequest(optional_request(request)), |r| expect_variant!(r, ListToolsResult => |x| x))
            .await?;
        if self.ctx.config.filter_tool_list {
            let before = result.tools.len();
            result.tools.retain(|t| self.authorize(&principal, "tools/list", Some(&t.name), None).is_allowed());
            tracing::debug!(server = %self.ctx.name, before, after = result.tools.len(), "filtered tools/list");
        }
        Ok(result)
    }

    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        self.ensure_registered(&context.peer);
        let principal = self.principal(&context.extensions)?;
        let tool = request.name.to_string();
        let decision = self.authorize(&principal, "tools/call", Some(&tool), request.arguments.as_ref());
        let logged_args = self
            .ctx
            .log_arguments
            .then(|| request.arguments.as_ref().map(|a| serde_json::Value::Object(a.clone())))
            .flatten();
        if !decision.is_allowed() {
            audit::request(&self.ctx.name, Some(&principal.subject), principal.user.as_deref(), "tools/call", Some(&tool), &decision, None, None, logged_args.as_ref());
            return Err(denied(decision.reason()));
        }

        let started = Instant::now();
        let client_token = context.meta.get_progress_token();
        let registry = self.backend.registry().clone();
        let result: Result<CallToolResponse, McpError> = async {
            let peer = self.backend.peer().await.map_err(backend_error)?;
            // Strip the client's progress token: rmcp assigns a backend-side one
            // and we map progress back to the client's token ourselves.
            let mut params = request;
            params.meta = None;
            let handle = peer
                .send_request_with_option(
                    ClientRequest::CallToolRequest(CallToolRequest::new(params)),
                    PeerRequestOptions::with_timeout(self.backend.spec().request_timeout).reset_timeout_on_progress(),
                )
                .await
                .map_err(service_error)?;
            let backend_token = handle.progress_token.clone();
            if let Some(ct) = client_token.clone() {
                registry.register_progress(backend_token.clone(), ProgressRoute { peer: context.peer.clone(), client_token: ct });
            }
            let id = handle.id.clone();
            let bpeer = handle.peer.clone();
            let outcome = tokio::select! {
                r = handle.await_response() => r.map_err(service_error),
                _ = context.ct.cancelled() => {
                    let _ = bpeer.notify_cancelled(cancelled_param(id)).await;
                    Err(McpError::new(ErrorCode::INTERNAL_ERROR, "request cancelled", None))
                }
            };
            if client_token.is_some() {
                registry.unregister_progress(&backend_token);
            }
            expect_variant!(outcome?,
                CallToolResult => CallToolResponse::Complete,
                InputRequiredResult => CallToolResponse::InputRequired,
                CreateTaskResult => CallToolResponse::Task,
            )
        }
        .await;

        let err_text = result.as_ref().err().map(|e| e.message.to_string());
        audit::request(
            &self.ctx.name,
            Some(&principal.subject),
            principal.user.as_deref(),
            "tools/call",
            Some(&tool),
            &decision,
            Some(started.elapsed()),
            err_text.as_deref(),
            logged_args.as_ref(),
        );
        result
    }

    async fn list_prompts(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListPromptsResult, McpError> {
        self.forward(&context, "prompts/list", ClientRequest::ListPromptsRequest(optional_request(request)), |r| expect_variant!(r, ListPromptsResult => |x| x)).await
    }

    async fn get_prompt(&self, request: GetPromptRequestParams, context: RequestContext<RoleServer>) -> Result<GetPromptResponse, McpError> {
        self.forward(&context, "prompts/get", ClientRequest::GetPromptRequest(GetPromptRequest::new(request)), |r| {
            expect_variant!(r, GetPromptResult => GetPromptResponse::Complete, InputRequiredResult => GetPromptResponse::InputRequired)
        })
        .await
    }

    async fn list_resources(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListResourcesResult, McpError> {
        self.forward(&context, "resources/list", ClientRequest::ListResourcesRequest(optional_request(request)), |r| expect_variant!(r, ListResourcesResult => |x| x)).await
    }

    async fn list_resource_templates(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListResourceTemplatesResult, McpError> {
        self.forward(&context, "resources/templates/list", ClientRequest::ListResourceTemplatesRequest(optional_request(request)), |r| {
            expect_variant!(r, ListResourceTemplatesResult => |x| x)
        })
        .await
    }

    async fn read_resource(&self, request: ReadResourceRequestParams, context: RequestContext<RoleServer>) -> Result<ReadResourceResponse, McpError> {
        self.forward(&context, "resources/read", ClientRequest::ReadResourceRequest(ReadResourceRequest::new(request)), |r| {
            expect_variant!(r, ReadResourceResult => ReadResourceResponse::Complete, InputRequiredResult => ReadResourceResponse::InputRequired)
        })
        .await
    }

    async fn complete(&self, request: CompleteRequestParams, context: RequestContext<RoleServer>) -> Result<CompleteResult, McpError> {
        self.forward(&context, "completion/complete", ClientRequest::CompleteRequest(CompleteRequest::new(request)), |r| expect_variant!(r, CompleteResult => |x| x)).await
    }

    async fn set_level(&self, request: SetLevelRequestParams, context: RequestContext<RoleServer>) -> Result<(), McpError> {
        self.forward(&context, "logging/setLevel", ClientRequest::SetLevelRequest(SetLevelRequest::new(request)), |r| expect_variant!(r, EmptyResult => |_| ())).await
    }

    #[allow(deprecated)]
    async fn subscribe(&self, request: SubscribeRequestParams, context: RequestContext<RoleServer>) -> Result<(), McpError> {
        self.forward(&context, "resources/subscribe", ClientRequest::SubscribeRequest(SubscribeRequest::new(request)), |r| expect_variant!(r, EmptyResult => |_| ())).await
    }

    #[allow(deprecated)]
    async fn unsubscribe(&self, request: UnsubscribeRequestParams, context: RequestContext<RoleServer>) -> Result<(), McpError> {
        self.forward(&context, "resources/unsubscribe", ClientRequest::UnsubscribeRequest(UnsubscribeRequest::new(request)), |r| expect_variant!(r, EmptyResult => |_| ())).await
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.ensure_registered(&context.peer);
        tracing::debug!(server = %self.ctx.name, "client initialized");
    }
}
