//! End-to-end tests for the built-in authorization server: a fake upstream
//! OpenID Connect provider, real HTTP against the gateway, the whole
//! register → authorize → upstream login → consent → code → token → MCP call
//! → refresh dance, plus the failure paths a client or an attacker can hit.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use host_my_mcp::{Config, build_app};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{CallToolRequestParams, ClientConfig},
    service::RunningService,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};

const ECHO_BIN: &str = env!("CARGO_BIN_EXE_host-my-mcp-echo");
const PRIVATE_PEM: &str = include_str!("fixtures/test_rsa.pem");
const JWKS: &str = include_str!("fixtures/jwks.json");
const UPSTREAM_CLIENT_ID: &str = "gateway-client-id.apps.example";
const UPSTREAM_CLIENT_SECRET: &str = "shh";

// ----- fake OpenID Connect provider -----

type IssuedCode = (String, String, String);

#[derive(Clone)]
struct FakeIdp {
    issuer: String,
    /// Who signs in next: (sub, email).
    identity: Arc<Mutex<(String, String)>>,
    /// code → (nonce, code_challenge, redirect_uri)
    codes: Arc<Mutex<HashMap<String, IssuedCode>>>,
    token_calls: Arc<Mutex<u32>>,
}

fn sha256_b64url(s: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, s.as_bytes());
    URL_SAFE_NO_PAD.encode(d.as_ref())
}

async fn start_fake_idp() -> FakeIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let idp = FakeIdp {
        issuer: format!("http://{addr}"),
        identity: Arc::new(Mutex::new(("1057".into(), "brendan@example.com".into()))),
        codes: Default::default(),
        token_calls: Default::default(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(idp_discovery))
        .route("/authorize", get(idp_authorize))
        .route("/token", post(idp_token))
        .route(
            "/jwks",
            get(|| async { ([("content-type", "application/json")], JWKS) }),
        )
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

async fn idp_discovery(State(idp): State<FakeIdp>) -> axum::Json<Value> {
    axum::Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks", idp.issuer),
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
    }))
}

async fn idp_authorize(
    State(idp): State<FakeIdp>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], UPSTREAM_CLIENT_ID);
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(q["scope"].split(' ').any(|s| s == "openid"));
    let code = format!("upstream-code-{}", idp.codes.lock().unwrap().len());
    idp.codes.lock().unwrap().insert(
        code.clone(),
        (
            q["nonce"].clone(),
            q["code_challenge"].clone(),
            q["redirect_uri"].clone(),
        ),
    );
    Redirect::to(&format!(
        "{}?code={code}&state={}",
        q["redirect_uri"], q["state"]
    ))
    .into_response()
}

async fn idp_token(State(idp): State<FakeIdp>, body: String) -> Response {
    *idp.token_calls.lock().unwrap() += 1;
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_id"], UPSTREAM_CLIENT_ID);
    assert_eq!(form["client_secret"], UPSTREAM_CLIENT_SECRET);
    let Some((nonce, challenge, redirect_uri)) = idp.codes.lock().unwrap().remove(&form["code"])
    else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    assert_eq!(form["redirect_uri"], redirect_uri);
    assert_eq!(
        sha256_b64url(&form["code_verifier"]),
        challenge,
        "gateway must do PKCE towards the provider"
    );
    let (sub, email) = idp.identity.lock().unwrap().clone();
    let now = jsonwebtoken::get_current_timestamp();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let id_token = encode(
        &header,
        &json!({
            "iss": idp.issuer, "sub": sub, "aud": UPSTREAM_CLIENT_ID,
            "exp": now + 300, "iat": now, "nonce": nonce,
            "email": email, "email_verified": true, "name": "Brendan",
        }),
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap();
    axum::Json(json!({
        "access_token": "upstream-opaque",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    }))
    .into_response()
}

// ----- gateway harness -----

struct Gateway {
    addr: SocketAddr,
    _cancel: tokio_util::sync::CancellationToken,
    _state: tempfile::TempDir,
}

impl Gateway {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

async fn start_gateway(idp: &FakeIdp) -> Gateway {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = tempfile::tempdir().unwrap();
    let yaml = format!(
        r#"
listen: {{ host: 127.0.0.1, port: {port} }}
public_url: http://127.0.0.1:{port}
auth:
  state_dir: "{state}"
  access_token_ttl_secs: 120
  providers:
    google:
      issuer: {issuer}
      client_id: {UPSTREAM_CLIENT_ID}
      client_secret: {UPSTREAM_CLIENT_SECRET}
users:
  brendan:
    emails: ["brendan@example.com"]
  bob:
    subjects: ["google|2000"]
servers:
  echo:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    tools:
      allow: ["*"]
      deny: ["admin_*"]
  locked:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    scopes: ["locked:use"]
    tools:
      allow: ["echo"]
  bobs:
    command: "{ECHO_BIN}"
    allowed_users: [bob]
    tools:
      allow: ["*"]
"#,
        port = addr.port(),
        state = state.path().display(),
        issuer = idp.issuer,
    );
    let cfg = Config::parse(&yaml).expect("config parses");
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
        _cancel: cancel,
        _state: state,
    }
}

#[derive(Clone, Default)]
struct Noop;
impl ClientHandler for Noop {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn connect(
    url: &str,
    token: &str,
) -> Result<RunningService<RoleClient, Noop>, rmcp::service::ClientInitializeError> {
    let cfg = StreamableHttpClientTransportConfig::with_uri(url.to_string())
        .auth_header(token.to_string());
    Noop.serve(StreamableHttpClientTransport::from_config(cfg))
        .await
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish()
}

fn location(resp: &reqwest::Response) -> String {
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    resp.headers()["location"].to_str().unwrap().to_string()
}

fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(rand_bytes());
    let challenge = sha256_b64url(&verifier);
    (verifier, challenge)
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}

struct Flow<'a> {
    gw: &'a Gateway,
    http: reqwest::Client,
    client_id: String,
    redirect_uri: String,
}

impl Flow<'_> {
    async fn register(gw: &Gateway) -> Flow<'_> {
        let http = http_client();
        let redirect_uri = "http://127.0.0.1:6274/oauth/callback".to_string();
        let resp = http
            .post(gw.url("/oauth/register"))
            .json(&json!({
                "client_name": "MCP Inspector",
                "redirect_uris": [redirect_uri],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let reg: Value = resp.json().await.unwrap();
        assert!(reg.get("client_secret").is_none(), "public client");
        Flow {
            gw,
            http,
            client_id: reg["client_id"].as_str().unwrap().to_string(),
            redirect_uri,
        }
    }

    /// Run authorize → upstream → callback. Returns the callback response
    /// (consent page, redirect back to the client, or an error page).
    async fn authorize_through_login(
        &self,
        challenge: &str,
        resources: &[&str],
        scope: Option<&str>,
    ) -> reqwest::Response {
        let mut u = url::Url::parse(&self.gw.url("/oauth/authorize")).unwrap();
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &self.redirect_uri)
                .append_pair("state", "xyz")
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256");
            for r in resources {
                q.append_pair("resource", r);
            }
            if let Some(s) = scope {
                q.append_pair("scope", s);
            }
        }
        let resp = self.http.get(u).send().await.unwrap();
        let to_idp = location(&resp);
        let resp = self.http.get(&to_idp).send().await.unwrap();
        let back = location(&resp);
        assert!(back.starts_with(&self.gw.url("/oauth/callback")), "{back}");
        self.http.get(&back).send().await.unwrap()
    }

    async fn approve(&self, consent_html: &str) -> String {
        let txn = consent_html
            .split("name=\"txn\" value=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("consent page carries the transaction id")
            .to_string();
        let resp = self
            .http
            .post(self.gw.url("/oauth/consent"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body(&[("txn", txn.as_str()), ("action", "approve")]))
            .send()
            .await
            .unwrap();
        location(&resp)
    }

    async fn token(&self, form: &[(&str, &str)]) -> (reqwest::StatusCode, Value) {
        let resp = self
            .http
            .post(self.gw.url("/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body(form))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.headers()["cache-control"],
            "no-store",
            "token responses must not be cached"
        );
        (resp.status(), resp.json().await.unwrap())
    }
}

#[tokio::test]
async fn full_dance_with_google_shaped_provider() {
    let idp = start_fake_idp().await;
    let gw = start_gateway(&idp).await;
    let http = http_client();
    let echo_resource = gw.url("/echo");

    // Discovery: the mount points at the gateway itself as authorization server.
    let resp = http
        .post(&echo_resource)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let prm: Value = http
        .get(gw.url("/.well-known/oauth-protected-resource/echo"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["authorization_servers"][0], gw.url(""));
    let md: Value = http
        .get(gw.url("/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(md["issuer"], gw.url(""));
    assert_eq!(md["authorization_endpoint"], gw.url("/oauth/authorize"));
    assert_eq!(md["token_endpoint"], gw.url("/oauth/token"));
    assert_eq!(md["registration_endpoint"], gw.url("/oauth/register"));
    assert_eq!(md["code_challenge_methods_supported"][0], "S256");
    let oidc: Value = http
        .get(gw.url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(oidc["issuer"], md["issuer"]);
    let jwks: Value = http
        .get(md["jwks_uri"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jwks["keys"][0]["kty"], "OKP");

    // Register, authorize, sign in upstream, land on the consent page.
    let flow = Flow::register(&gw).await;
    let (verifier, challenge) = pkce();
    let resp = flow
        .authorize_through_login(&challenge, &[&echo_resource], None)
        .await;
    assert_eq!(resp.status(), 200, "first time: consent page");
    assert_eq!(resp.headers()["cache-control"], "no-store, no-transform");
    let csp = resp.headers()["content-security-policy"].to_str().unwrap();
    assert!(
        !csp.contains("form-action"),
        "Chrome applies form-action to the post-consent redirect: {csp}"
    );
    let consent = resp.text().await.unwrap();
    assert!(consent.contains("MCP Inspector"), "{consent}");
    assert!(consent.contains("brendan@example.com"), "{consent}");
    assert!(consent.contains("<code>echo</code>"), "{consent}");

    // Approve → code back at the client's redirect URI, with state and iss.
    let back = flow.approve(&consent).await;
    assert!(back.starts_with(&flow.redirect_uri), "{back}");
    let q = query(&back);
    assert_eq!(q["state"], "xyz");
    assert_eq!(q["iss"], gw.url(""));
    let code = q["code"].clone();

    // Wrong PKCE verifier burns the code.
    let (status, body) = flow
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            (
                "code_verifier",
                "wrong-verifier-wrong-verifier-wrong-verifier-wrong",
            ),
            ("client_id", &flow.client_id),
            ("redirect_uri", &flow.redirect_uri),
        ])
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    let (status, body) = flow
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &verifier),
            ("client_id", &flow.client_id),
        ])
        .await;
    assert_eq!(status, 400, "codes are single use: {body}");

    // Do it again properly; consent is remembered so the callback redirects.
    let (verifier, challenge) = pkce();
    let resp = flow
        .authorize_through_login(&challenge, &[&echo_resource], None)
        .await;
    let back = location(&resp);
    let code = query(&back)["code"].clone();
    let (status, tok) = flow
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &verifier),
            ("client_id", &flow.client_id),
            ("redirect_uri", &flow.redirect_uri),
            ("resource", &echo_resource),
        ])
        .await;
    assert_eq!(status, 200, "{tok}");
    assert_eq!(tok["token_type"], "Bearer");
    assert_eq!(tok["expires_in"], 120);
    let access = tok["access_token"].as_str().unwrap().to_string();
    let refresh = tok["refresh_token"].as_str().unwrap().to_string();

    // The access token is a JWT the gateway accepts for /echo …
    let client = connect(&echo_resource, &access)
        .await
        .expect("token works at the mount");
    let r = client
        .call_tool({
            let mut p = CallToolRequestParams::new("echo");
            p.arguments = json!({"text": "hi"}).as_object().cloned();
            p
        })
        .await
        .unwrap();
    assert!(
        r.content
            .iter()
            .any(|c| c.as_text().map(|t| t.text == "hi").unwrap_or(false))
    );
    client.cancel().await.unwrap();

    // … but not for /locked (not in aud) …
    let resp = http
        .post(gw.url("/locked"))
        .bearer_auth(&access)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "aud is bound to /echo");

    // … and the claims say who it is.
    let payload = access.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["sub"], "google|1057");
    assert_eq!(claims["email"], "brendan@example.com");
    assert_eq!(claims["user"], "brendan");
    assert_eq!(claims["aud"][0], echo_resource);
    assert_eq!(claims["client_id"], flow.client_id);

    // Refresh rotates; the old refresh token dies.
    let (status, tok2) = flow
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &flow.client_id),
        ])
        .await;
    assert_eq!(status, 200, "{tok2}");
    let refresh2 = tok2["refresh_token"].as_str().unwrap();
    assert_ne!(refresh2, refresh);
    connect(&echo_resource, tok2["access_token"].as_str().unwrap())
        .await
        .expect("refreshed token works")
        .cancel()
        .await
        .unwrap();
    let (status, body) = flow
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &flow.client_id),
        ])
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // Refresh may not widen to a resource that was not authorized.
    let locked = gw.url("/locked");
    let (status, body) = flow
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh2),
            ("client_id", &flow.client_id),
            ("resource", &locked),
        ])
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // Scopes: asking for /locked grants its advertised scope automatically.
    let (verifier, challenge) = pkce();
    let resp = flow
        .authorize_through_login(&challenge, &[&locked], None)
        .await;
    let code = query(&location(&resp))["code"].clone();
    let (status, tok) = flow
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &verifier),
            ("client_id", &flow.client_id),
        ])
        .await;
    assert_eq!(status, 200, "{tok}");
    assert_eq!(tok["scope"], "locked:use");
    connect(&locked, tok["access_token"].as_str().unwrap())
        .await
        .expect("scope requirement satisfied")
        .cancel()
        .await
        .unwrap();

    // Google was consulted once per login, never for refreshes.
    assert_eq!(*idp.token_calls.lock().unwrap(), 3);
}

#[tokio::test]
async fn rejects_unknown_identity_wrong_server_bad_clients_and_bad_requests() {
    let idp = start_fake_idp().await;
    let gw = start_gateway(&idp).await;
    let http = http_client();
    let echo_resource = gw.url("/echo");
    let flow = Flow::register(&gw).await;

    // An identity not under `users` sees a page naming its subject and email.
    *idp.identity.lock().unwrap() = ("9999".into(), "stranger@example.com".into());
    let (_, challenge) = pkce();
    let resp = flow
        .authorize_through_login(&challenge, &[&echo_resource], None)
        .await;
    assert_eq!(resp.status(), 403);
    let page = resp.text().await.unwrap();
    assert!(page.contains("google|9999"), "{page}");
    assert!(page.contains("stranger@example.com"), "{page}");
    assert!(page.contains("error=access_denied"), "return link: {page}");

    // A known user asking for a server they are not allowed on.
    *idp.identity.lock().unwrap() = ("1057".into(), "brendan@example.com".into());
    let bobs = gw.url("/bobs");
    let resp = flow
        .authorize_through_login(&challenge, &[&bobs], None)
        .await;
    assert_eq!(resp.status(), 403);
    assert!(resp.text().await.unwrap().contains("bobs"));

    // Unknown resource → redirect with invalid_target (redirect_uri is trusted).
    let u = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state=s&code_challenge={challenge}&code_challenge_method=S256&resource=https://elsewhere.example/x",
        gw.url("/oauth/authorize"),
        flow.client_id,
        flow.redirect_uri
    );
    let q = query(&location(&http.get(&u).send().await.unwrap()));
    assert_eq!(q["error"], "invalid_target");
    assert_eq!(q["state"], "s");

    // Missing PKCE → invalid_request; non-S256 → invalid_request.
    let u = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&resource={echo_resource}",
        gw.url("/oauth/authorize"),
        flow.client_id,
        flow.redirect_uri
    );
    assert_eq!(
        query(&location(&http.get(&u).send().await.unwrap()))["error"],
        "invalid_request"
    );
    let u = format!("{u}&code_challenge=abc&code_challenge_method=plain");
    assert_eq!(
        query(&location(&http.get(&u).send().await.unwrap()))["error"],
        "invalid_request"
    );

    // Unregistered redirect_uri or unknown client: shown, never redirected.
    let u = format!(
        "{}?response_type=code&client_id={}&redirect_uri=https://evil.example/cb&code_challenge={challenge}&code_challenge_method=S256",
        gw.url("/oauth/authorize"),
        flow.client_id
    );
    let resp = http.get(&u).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let u = format!(
        "{}?response_type=code&client_id=nope&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
        gw.url("/oauth/authorize"),
        flow.redirect_uri
    );
    assert_eq!(http.get(&u).send().await.unwrap().status(), 400);

    // Registration validation.
    for (body, err) in [
        (json!({"redirect_uris": []}), "invalid_redirect_uri"),
        (
            json!({"redirect_uris": ["http://example.com/cb"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris": ["https://ok.example/cb"], "token_endpoint_auth_method": "private_key_jwt"}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": ["https://ok.example/cb"], "grant_types": ["implicit"]}),
            "invalid_client_metadata",
        ),
    ] {
        let resp = http
            .post(gw.url("/oauth/register"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{body}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], err, "{body}");
    }

    // A confidential client must present its secret; loopback ports may vary.
    let resp = http
        .post(gw.url("/oauth/register"))
        .json(
            &json!({"redirect_uris": ["http://127.0.0.1:1234/cb"], "client_name": "Confidential"}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let reg: Value = resp.json().await.unwrap();
    let cid = reg["client_id"].as_str().unwrap();
    let secret = reg["client_secret"].as_str().unwrap();
    let conf = Flow {
        gw: &gw,
        http: http_client(),
        client_id: cid.to_string(),
        redirect_uri: "http://127.0.0.1:9876/cb".into(),
    };
    let (verifier, challenge) = pkce();
    let resp = conf
        .authorize_through_login(&challenge, &[&echo_resource], Some("openid email"))
        .await;
    let consent = resp.text().await.unwrap();
    let code = query(&conf.approve(&consent).await)["code"].clone();
    let (status, body) = conf
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &verifier),
            ("client_id", cid),
        ])
        .await;
    assert_eq!(status, 401, "no secret: {body}");
    assert_eq!(body["error"], "invalid_client");
    // The code was consumed by the failed attempt? No: client auth fails first.
    let resp = conf
        .http
        .post(gw.url("/oauth/token"))
        .basic_auth(cid, Some(secret))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let tok: Value = resp.json().await.unwrap();
    assert_eq!(tok["scope"], "email openid");

    // A refresh token presented by another client is rejected.
    let (status, body) = flow
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", tok["refresh_token"].as_str().unwrap()),
            ("client_id", &flow.client_id),
        ])
        .await;
    assert_eq!(status, 400, "{body}");

    // Unsupported grant and garbage.
    let (status, body) = flow
        .token(&[("grant_type", "password"), ("client_id", &flow.client_id)])
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "unsupported_grant_type");
    let (status, body) = flow.token(&[("grant_type", "authorization_code")]).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn state_survives_restart_and_oauth_paths_are_reserved() {
    let idp = start_fake_idp().await;
    let state = tempfile::tempdir().unwrap();
    let yaml = |port: u16| {
        format!(
            r#"
listen: {{ host: 127.0.0.1, port: {port} }}
public_url: http://127.0.0.1:{port}
auth:
  state_dir: "{state}"
  providers:
    google: {{ issuer: {issuer}, client_id: x, client_secret: y }}
users:
  brendan: {{ emails: ["brendan@example.com"] }}
servers:
  echo:
    command: "{ECHO_BIN}"
    allowed_users: [brendan]
    tools: {{ allow: ["*"] }}
"#,
            state = state.path().display(),
            issuer = idp.issuer,
        )
    };
    let first = {
        let cfg = Config::parse(&yaml(18080)).unwrap();
        let app = build_app(cfg).await.unwrap();
        let jwks = app.state.config.auth.state_dir();
        app.shutdown();
        jwks
    };
    assert!(first.join("signing-key.pkcs8").exists());
    let cfg = Config::parse(&yaml(18080)).unwrap();
    let app = build_app(cfg).await.unwrap();
    app.shutdown();

    // /oauth/* is reserved for the authorization server.
    let bad = yaml(18080).replace("  echo:\n", "  echo:\n    path: /oauth/x\n");
    let err = Config::parse(&bad).unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");

    // providers and issuer are mutually exclusive.
    let bad = yaml(18080).replace("auth:\n", "auth:\n  issuer: https://tenant.us.auth0.com/\n");
    assert!(Config::parse(&bad).is_err());

    // users is required in built-in mode.
    let bad = yaml(18080).replace(
        "users:\n  brendan: { emails: [\"brendan@example.com\"] }\n",
        "",
    );
    let bad = bad.replace("allowed_users: [brendan]", "allowed_users: [\"*\"]");
    let err = Config::parse(&bad).unwrap_err().to_string();
    assert!(err.contains("users"), "{err}");
}
