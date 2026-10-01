//! A tiny stdio MCP server used by the integration tests and handy as a first
//! backend when trying the gateway. Tools:
//!
//! - `echo { text }`      returns the text
//! - `whoami {}`          returns the process environment variable `ECHO_IDENTITY`
//! - `slow { steps }`     emits `steps` progress notifications then returns
//! - `fail {}`            returns an `isError` tool result
//! - `admin_reset {}`     exists only so tool policy has something to deny
//! - `crash {}`           exits the process immediately (restart testing)
//!
//! Log lines go to stderr; stdout is reserved for MCP framing.

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
        InitializeResult, ListToolsResult, PaginatedRequestParams, ProgressNotificationParam,
        ProtocolVersion, ServerCapabilities, Tool,
    },
    service::RequestContext,
    transport::stdio,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct Echo;

fn tool(name: &'static str, description: &'static str, schema: serde_json::Value) -> Tool {
    Tool::new(name, description, Arc::new(schema.as_object().cloned().unwrap_or_default()))
}

impl ServerHandler for Echo {
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
            .with_server_info(Implementation::new("host-my-mcp-echo", env!("CARGO_PKG_VERSION")))
            .with_instructions("Test backend for host-my-mcp.")
    }

    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, _ctx: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        let obj = |props: serde_json::Value, required: Vec<&str>| json!({"type": "object", "properties": props, "required": required});
        Ok(ListToolsResult::with_all_items(vec![
            tool("echo", "Echo text back", obj(json!({"text": {"type": "string"}}), vec!["text"])),
            tool("whoami", "Report ECHO_IDENTITY from the environment", obj(json!({}), vec![])),
            tool("slow", "Emit N progress notifications", obj(json!({"steps": {"type": "integer"}}), vec![])),
            tool("fail", "Always fails", obj(json!({}), vec![])),
            tool("admin_reset", "Pretend to do something dangerous", obj(json!({}), vec![])),
            tool("crash", "Exit the process immediately", obj(json!({}), vec![])),
        ]))
    }

    async fn call_tool(&self, request: CallToolRequestParams, ctx: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        let args = request.arguments.unwrap_or_default();
        let result = match request.name.as_ref() {
            "echo" => {
                let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
                CallToolResult::success(vec![ContentBlock::text(text)])
            }
            "whoami" => CallToolResult::success(vec![ContentBlock::text(std::env::var("ECHO_IDENTITY").unwrap_or_else(|_| "unset".into()))]),
            "slow" => {
                let steps = args.get("steps").and_then(|v| v.as_u64()).unwrap_or(3);
                if let Some(token) = ctx.meta.get_progress_token() {
                    for i in 1..=steps {
                        let _ = ctx
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), i as f64)
                                    .with_total(steps as f64)
                                    .with_message(format!("step {i}")),
                            )
                            .await;
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
                CallToolResult::success(vec![ContentBlock::text(format!("done after {steps} steps"))])
            }
            "fail" => CallToolResult::error(vec![ContentBlock::text("the tool failed on purpose")]),
            "admin_reset" => CallToolResult::success(vec![ContentBlock::text("reset!")]),
            "crash" => {
                tracing::error!("crash requested; exiting");
                std::process::exit(3);
            }
            other => return Err(McpError::invalid_params(format!("unknown tool {other}"), None)),
        };
        Ok(CallToolResponse::Complete(result))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    ).init();
    tracing::info!("host-my-mcp-echo starting");
    let service = Echo.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
