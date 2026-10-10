//! End-to-end tests: real HTTP, real child process (the `host-my-mcp-echo`
//! binary), real JWTs against a locally served JWKS.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, routing::get};
use host_my_mcp::{Config, build_app};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmcp::{
    ClientHandler, RoleClient, ServiceError, ServiceExt,
    model::{CallToolRequestParams, ClientConfig, ProgressNotificationParam},
    service::{NotificationContext, RunningService},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};

const ECHO_BIN: &str = env!("CARGO_BIN_EXE_host-my-mcp-echo");
const PRIVATE_PEM: &str = include_str!("fixtures/test_rsa.pem");
const JWKS: &str = include_str!("fixtures/jwks.json");
const ISSUER: &str = "https://tenant.us.auth0.com/";

#[derive(Clone, Default)]
struct Recorder {
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
}

impl ClientHandler for Recorder {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        self.progress.lock().unwrap().push(params);
    }
}

struct Gateway {
    addr: SocketAddr,
    _app_cancel: tokio_util::sync::CancellationToken,
}

impl Gateway {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

async fn start_gateway(yaml: impl Fn(u16) -> String) -> Gateway {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Config::parse(&yaml(addr.port())).expect("config parses");
    let app = build_app(cfg).await.expect("app builds");
    let cancel = app.cancel.clone();
    let backends = app.backends();
    let router = app.router;
    let ct = cancel.clone();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                ct.cancelled().await;
                for b in backends {
                    b.shutdown();
                }
            })
            .await
            .unwrap();
    });
    Gateway {
        addr,
        _app_cancel: cancel,
    }
}

async fn connect(
    url: &str,
    token: Option<&str>,
) -> Result<RunningService<RoleClient, Recorder>, rmcp::service::ClientInitializeError> {
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(url.to_string());
    if let Some(t) = token {
        cfg = cfg.auth_header(t.to_string());
    }
    let transport = StreamableHttpClientTransport::from_config(cfg);
    Recorder::default().serve(transport).await
}

fn call(name: &str, args: Value) -> CallToolRequestParams {
    let mut p = CallToolRequestParams::new(name.to_string());
    p.arguments = args.as_object().cloned();
    p
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("")
}

fn no_auth_config(port: u16) -> String {
    format!(
        r#"
listen: {{ host: 127.0.0.1, port: {port} }}
public_url: http://127.0.0.1:{port}
auth:
  disabled: true
servers:
  echo:
    command: "{ECHO_BIN}"
    env:
      ECHO_IDENTITY: gateway-test
    allowed_users: ["*"]
    restart: {{ max_restarts: 1, window_secs: 60, cooldown_secs: 60 }}
    tools:
      allow: ["*"]
      deny: ["admin_*"]
"#
    )
}

#[tokio::test]
async fn unauthenticated_bridge_roundtrip() {
    let gw = start_gateway(no_auth_config).await;

    // health + status before any session
    let http = reqwest::Client::new();
    assert_eq!(
        http.get(gw.url("/healthz")).send().await.unwrap().status(),
        200
    );
    let status: Value = http
        .get(gw.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        status["servers"][0]["backend"]["state"], "stopped",
        "lazy backend not yet started"
    );

    let client = connect(&gw.url("/echo"), None)
        .await
        .expect("initialize through gateway");
    let info = client.peer_info().expect("server info");
    assert_eq!(info.server_info.as_ref().unwrap().name, "host-my-mcp-echo");
    assert!(
        info.instructions
            .as_deref()
            .unwrap_or("")
            .contains("Test backend")
    );
    assert!(info.capabilities.tools.is_some());

    // tools/list is filtered by policy: admin_reset is denied
    let tools = client.list_tools(None).await.unwrap();
    let names: Vec<_> = tools.tools.iter().map(|t| t.name.to_string()).collect();
    assert!(names.contains(&"echo".to_string()));
    assert!(names.contains(&"whoami".to_string()));
    assert!(
        !names.contains(&"admin_reset".to_string()),
        "denied tool must be hidden: {names:?}"
    );

    // tools/call forwards
    let r = client
        .call_tool(call("echo", json!({"text": "hello"})))
        .await
        .unwrap();
    assert_eq!(text_of(&r), "hello");
    let r = client.call_tool(call("whoami", json!({}))).await.unwrap();
    assert_eq!(
        text_of(&r),
        "gateway-test",
        "env from config reaches the child"
    );

    // tool-level error passes through as a tool result, not a protocol error
    let r = client.call_tool(call("fail", json!({}))).await.unwrap();
    assert_eq!(r.is_error, Some(true));

    // denied tool never reaches the backend
    let err = client
        .call_tool(call("admin_reset", json!({})))
        .await
        .unwrap_err();
    match err {
        ServiceError::McpError(e) => assert!(e.message.contains("forbidden"), "{e:?}"),
        other => panic!("expected McpError, got {other:?}"),
    }

    let status: Value = http
        .get(gw.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["servers"][0]["backend"]["state"], "running");
    assert_eq!(status["servers"][0]["backend"]["sessions"], 1);

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn progress_is_routed_per_session() {
    let gw = start_gateway(no_auth_config).await;
    let a = connect(&gw.url("/echo"), None).await.unwrap();
    let b = connect(&gw.url("/echo"), None).await.unwrap();

    let (ra, rb) = tokio::join!(
        a.call_tool(call("slow", json!({"steps": 3}))),
        b.call_tool(call("slow", json!({"steps": 5}))),
    );
    assert!(text_of(&ra.unwrap()).contains("3 steps"));
    assert!(text_of(&rb.unwrap()).contains("5 steps"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let pa = a.service().progress.lock().unwrap().clone();
    let pb = b.service().progress.lock().unwrap().clone();
    assert_eq!(
        pa.len(),
        3,
        "session A must see exactly its own progress: {pa:?}"
    );
    assert_eq!(
        pb.len(),
        5,
        "session B must see exactly its own progress: {pb:?}"
    );
    // Tokens were translated back to what each client's peer issued.
    let ta: std::collections::HashSet<_> = pa
        .iter()
        .map(|p| format!("{:?}", p.progress_token))
        .collect();
    let tb: std::collections::HashSet<_> = pb
        .iter()
        .map(|p| format!("{:?}", p.progress_token))
        .collect();
    assert_eq!(ta.len(), 1);
    assert_eq!(tb.len(), 1);

    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
}

#[tokio::test]
async fn backend_restarts_within_budget_then_fails_closed() {
    let gw = start_gateway(no_auth_config).await;
    let client = connect(&gw.url("/echo"), None).await.unwrap();

    // First crash: the in-flight call fails, the next call restarts the child.
    let err = client
        .call_tool(call("crash", json!({})))
        .await
        .unwrap_err();
    assert!(matches!(err, ServiceError::McpError(_)), "{err:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = client
        .call_tool(call("echo", json!({"text": "back"})))
        .await
        .unwrap();
    assert_eq!(text_of(&r), "back");

    let status: Value = reqwest::get(gw.url("/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["servers"][0]["backend"]["restarts_in_window"], 1);

    // Second crash exhausts max_restarts: 1 → cooldown, requests fail closed.
    let _ = client
        .call_tool(call("crash", json!({})))
        .await
        .unwrap_err();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let err = client
        .call_tool(call("echo", json!({"text": "x"})))
        .await
        .unwrap_err();
    match err {
        ServiceError::McpError(e) => assert!(e.message.contains("backend unavailable"), "{e:?}"),
        other => panic!("{other:?}"),
    }
    let status: Value = reqwest::get(gw.url("/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["servers"][0]["backend"]["state"], "failed");

    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// OAuth

async fn start_jwks_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/jwks.json",
        get(|| async { ([("content-type", "application/json")], JWKS) }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

fn mint(sub: &str, aud: &str, scope: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    header.typ = Some("at+jwt".into());
    let claims = json!({
        "iss": ISSUER, "sub": sub, "aud": [aud], "exp": now() + 300, "iat": now(), "scope": scope,
    });
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn oauth_resource_server_behaviour() {
    let jwks = start_jwks_server().await;
    let gw = start_gateway(|port| {
        format!(
            r#"
listen: {{ host: 127.0.0.1, port: {port} }}
public_url: http://127.0.0.1:{port}
auth:
  issuer: {ISSUER}
  jwks_uri: http://{jwks}/jwks.json
users:
  brendan:
    subjects: ["google-oauth2|123"]
servers:
  echo:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    tools:
      allow: ["*"]
  locked:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    scopes: ["locked:use"]
    tools:
      allow: ["echo"]
"#
        )
    })
    .await;
    let http = reqwest::Client::new();
    let echo_resource = gw.url("/echo");
    let locked_resource = gw.url("/locked");
    let init_body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});

    // 1. No token → 401 + challenge pointing at the path-inserted metadata URL.
    let resp = http
        .post(&echo_resource)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let www = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let md_url = gw.url("/.well-known/oauth-protected-resource/echo");
    assert!(www.starts_with("Bearer "), "{www}");
    assert!(
        www.contains(&format!("resource_metadata=\"{md_url}\"")),
        "{www}"
    );

    // 2. Protected resource metadata (RFC 9728).
    let md: Value = http
        .get(&md_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(md["resource"], echo_resource);
    assert_eq!(md["authorization_servers"][0], ISSUER);
    assert_eq!(md["bearer_methods_supported"][0], "header");
    let locked_md: Value = http
        .get(gw.url("/.well-known/oauth-protected-resource/locked"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(locked_md["scopes_supported"][0], "locked:use");
    assert_eq!(
        http.get(gw.url("/.well-known/oauth-protected-resource/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // 3. Token minted for /locked cannot be used at /echo (audience binding).
    let wrong = mint("google-oauth2|123", &locked_resource, "");
    let resp = http
        .post(&echo_resource)
        .bearer_auth(&wrong)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );

    // 4. Valid token for an identity that is not configured → 403.
    let stranger = mint("google-oauth2|999", &echo_resource, "");
    let resp = http
        .post(&echo_resource)
        .bearer_auth(&stranger)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");

    // 5. Right user, missing required scope → 403 insufficient_scope with scope hint.
    let unscoped = mint("google-oauth2|123", &locked_resource, "openid");
    let resp = http
        .post(&locked_resource)
        .bearer_auth(&unscoped)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let www = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        www.contains("insufficient_scope") && www.contains("scope=\"locked:use\""),
        "{www}"
    );

    // 6. Garbage token → 401, never 500.
    let resp = http
        .post(&echo_resource)
        .bearer_auth("not-a-jwt")
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 7. Happy path through a real MCP client, both servers, no cross-use.
    let good = mint("google-oauth2|123", &echo_resource, "openid");
    let client = connect(&echo_resource, Some(&good))
        .await
        .expect("authorized initialize");
    let r = client
        .call_tool(call("echo", json!({"text": "secure"})))
        .await
        .unwrap();
    assert_eq!(text_of(&r), "secure");
    client.cancel().await.unwrap();

    let scoped = mint("google-oauth2|123", &locked_resource, "openid locked:use");
    let client = connect(&locked_resource, Some(&scoped))
        .await
        .expect("scoped initialize");
    let tools = client.list_tools(None).await.unwrap();
    assert_eq!(tools.tools.len(), 1, "only `echo` is allowed on locked");
    client.cancel().await.unwrap();

    // The scoped /locked token is still rejected at /echo.
    assert!(connect(&echo_resource, Some(&scoped)).await.is_err());
}

// ---------------------------------------------------------------------------
// CORS for browser clients

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .reduce(|a, b| format!("{a}, {b}"))
}

fn assert_no_cors(resp: &reqwest::Response, what: &str) {
    for h in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
    ] {
        assert!(
            header(resp, h).is_none(),
            "{what}: unexpected {h}: {:?}",
            resp.headers()
        );
    }
}

fn assert_vary_origin(resp: &reqwest::Response, what: &str) {
    let vary = header(resp, "vary").unwrap_or_default();
    assert!(
        vary.split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("origin")),
        "{what}: Vary must name Origin, got {vary:?}"
    );
}

const BROWSER: &str = "http://localhost:5173";
const STRANGER: &str = "https://evil.example";

#[tokio::test]
async fn cors_for_allowed_browser_origins() {
    let jwks = start_jwks_server().await;
    let gw = start_gateway(|port| {
        format!(
            r#"
listen:
  host: 127.0.0.1
  port: {port}
  allowed_origins: ["{BROWSER}", "http://127.0.0.1:*"]
public_url: http://127.0.0.1:{port}
auth:
  issuer: {ISSUER}
  jwks_uri: http://{jwks}/jwks.json
users:
  brendan:
    subjects: ["google-oauth2|123"]
servers:
  echo:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    tools:
      allow: ["*"]
"#
        )
    })
    .await;
    let http = reqwest::Client::new();
    let echo = gw.url("/echo");
    let md_url = gw.url("/.well-known/oauth-protected-resource/echo");
    let init_body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});

    // Preflight on the server path from an allowed origin: 204, no token needed.
    let resp = http
        .request(reqwest::Method::OPTIONS, &echo)
        .header("origin", BROWSER)
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization, content-type, mcp-session-id",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "{:?}", resp.headers());
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some(BROWSER)
    );
    assert_vary_origin(&resp, "preflight");
    assert_eq!(
        header(&resp, "access-control-allow-methods").as_deref(),
        Some("GET, POST, DELETE, OPTIONS")
    );
    let allow_headers = header(&resp, "access-control-allow-headers")
        .unwrap()
        .to_ascii_lowercase();
    for h in [
        "authorization",
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
    ] {
        assert!(
            allow_headers.contains(h),
            "allow-headers missing {h}: {allow_headers}"
        );
    }
    assert_eq!(
        header(&resp, "access-control-max-age").as_deref(),
        Some("600")
    );
    assert!(
        header(&resp, "www-authenticate").is_none(),
        "preflight must not be intercepted by auth"
    );

    // Port wildcard entries work too.
    let resp = http
        .request(reqwest::Method::OPTIONS, &echo)
        .header("origin", "http://127.0.0.1:4242")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some("http://127.0.0.1:4242")
    );

    // Preflight from an origin that is not listed: no CORS headers at all.
    let resp = http
        .request(reqwest::Method::OPTIONS, &echo)
        .header("origin", STRANGER)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 204);
    assert_no_cors(&resp, "preflight from stranger");

    // Unauthenticated POST from the browser: the 401 challenge is readable cross-origin.
    let resp = http
        .post(&echo)
        .header("origin", BROWSER)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        header(&resp, "www-authenticate")
            .unwrap()
            .contains("resource_metadata=")
    );
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some(BROWSER)
    );
    assert_vary_origin(&resp, "401");
    let expose = header(&resp, "access-control-expose-headers")
        .unwrap()
        .to_ascii_lowercase();
    for h in ["www-authenticate", "mcp-session-id", "mcp-protocol-version"] {
        assert!(expose.contains(h), "expose-headers missing {h}: {expose}");
    }

    // Protected-resource metadata: GET and preflight both carry CORS headers.
    let resp = http
        .get(&md_url)
        .header("origin", BROWSER)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some(BROWSER)
    );
    assert_vary_origin(&resp, "metadata");
    assert!(header(&resp, "access-control-expose-headers").is_some());
    let md: Value = resp.json().await.unwrap();
    assert_eq!(md["resource"], echo);
    let resp = http
        .request(reqwest::Method::OPTIONS, &md_url)
        .header("origin", BROWSER)
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some(BROWSER)
    );

    // Authenticated request from the browser: success response carries CORS headers
    // and the session id is exposed so the client can read it.
    let good = mint("google-oauth2|123", &echo, "openid");
    let resp = http
        .post(&echo)
        .header("origin", BROWSER)
        .header("accept", "application/json, text/event-stream")
        .bearer_auth(&good)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.headers());
    assert!(header(&resp, "mcp-session-id").is_some());
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some(BROWSER)
    );
    assert_vary_origin(&resp, "authenticated");
    assert!(
        header(&resp, "access-control-expose-headers")
            .unwrap()
            .to_ascii_lowercase()
            .contains("mcp-session-id")
    );

    // Origin validation is still enforced by the transport for unlisted origins,
    // and the rejection carries no CORS headers.
    let resp = http
        .post(&echo)
        .header("origin", STRANGER)
        .header("accept", "application/json, text/event-stream")
        .bearer_auth(&good)
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_no_cors(&resp, "stranger POST");

    // Requests without an Origin header (non-browser clients) are untouched.
    let resp = http.get(&md_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_no_cors(&resp, "no Origin");
}

#[tokio::test]
async fn no_cors_headers_without_allowed_origins() {
    let gw = start_gateway(no_auth_config).await;
    let http = reqwest::Client::new();
    let echo = gw.url("/echo");
    let init_body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});

    let resp = http
        .request(reqwest::Method::OPTIONS, &echo)
        .header("origin", BROWSER)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 204);
    assert_no_cors(&resp, "preflight");

    // Origin validation is off, so the request succeeds, but nothing is exposed to browsers.
    let resp = http
        .post(&echo)
        .header("origin", BROWSER)
        .header("accept", "application/json, text/event-stream")
        .json(&init_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_no_cors(&resp, "POST");

    let resp = http
        .get(gw.url("/.well-known/oauth-protected-resource/echo"))
        .header("origin", BROWSER)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_no_cors(&resp, "metadata");
}

#[test]
fn wildcard_cors_origin_is_rejected_by_config() {
    let yaml = no_auth_config(8080).replace(
        "listen: { host: 127.0.0.1, port: 8080 }",
        "listen: { host: 127.0.0.1, port: 8080, allowed_origins: [\"*\"] }",
    );
    let err = Config::parse(&yaml).unwrap_err().to_string();
    assert!(
        err.contains("listen.allowed_origins") && err.contains("`*` is not accepted"),
        "{err}"
    );
}
