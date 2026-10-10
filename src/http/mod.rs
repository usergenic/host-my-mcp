//! axum application: one Streamable HTTP MCP endpoint per configured server,
//! RFC 9728 metadata, health and status.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;

use crate::{
    auth::{
        AuthLayerState, JwksCache, ProtectedResourceMetadata, TokenValidator,
        metadata::metadata_url, require_auth,
    },
    backend::{Backend, BackendSpec, BackendStatus},
    bridge::{ServerContext, registry::SessionRegistry},
    config::{Config, Start},
    policy::StaticPolicy,
};

/// Shared state for the non-MCP routes.
pub struct AppState {
    pub config: Config,
    pub servers: Vec<Arc<ServerContext>>,
    pub metadata: std::collections::HashMap<String, ProtectedResourceMetadata>,
}

pub struct App {
    pub router: Router,
    pub state: Arc<AppState>,
    /// Cancel to stop all MCP sessions and backends.
    pub cancel: CancellationToken,
}

impl App {
    pub fn backends(&self) -> Vec<Arc<Backend>> {
        self.state
            .servers
            .iter()
            .map(|s| s.shared_backend.clone())
            .collect()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
        for b in self.backends() {
            b.shutdown();
        }
    }
}

/// Build the router and supervisors from configuration. Eager backends are
/// started here; a failing eager backend is logged, not fatal, so one broken
/// server cannot keep the others offline.
pub async fn build_app(config: Config) -> anyhow::Result<App> {
    let cancel = CancellationToken::new();
    let policy = StaticPolicy::from_config(&config);

    let validator: Option<Arc<TokenValidator>> = if config.auth.disabled {
        tracing::warn!(
            "AUTHENTICATION IS DISABLED (auth.disabled: true); every request is anonymous"
        );
        None
    } else {
        let jwks_uri = config
            .auth
            .jwks_uri()
            .ok_or_else(|| anyhow::anyhow!("cannot derive jwks_uri from issuer"))?;
        let cache = JwksCache::new(
            jwks_uri.clone(),
            Duration::from_secs(config.auth.jwks_min_refresh_secs),
            Duration::from_secs(config.auth.jwks_max_age_secs),
        );
        match cache.warm().await {
            Ok(n) => tracing::info!(%jwks_uri, keys = n, "loaded signing keys"),
            Err(e) => {
                tracing::warn!(%jwks_uri, error = %e, "could not load signing keys at startup; will retry on first request (requests fail closed until then)")
            }
        }
        Some(Arc::new(TokenValidator::new(&config.auth, cache)?))
    };

    let public_origin = config.public_origin();
    let public_host = config
        .public_url
        .host_str()
        .unwrap_or("localhost")
        .to_string();
    let mut allowed_hosts: Vec<String> = vec![
        public_host.clone(),
        format!(
            "{}:{}",
            public_host,
            config.public_url.port_or_known_default().unwrap_or(443)
        ),
        "localhost".into(),
        format!("localhost:{}", config.listen.port),
        "127.0.0.1".into(),
        format!("127.0.0.1:{}", config.listen.port),
        "::1".into(),
        format!("[::1]:{}", config.listen.port),
        config.listen.host.clone(),
        format!("{}:{}", config.listen.host, config.listen.port),
    ];
    allowed_hosts.extend(config.listen.allowed_hosts.iter().cloned());
    let disable_host_check = config.listen.allowed_hosts.iter().any(|h| h == "*");

    let mut router = Router::new();
    let mut servers = Vec::new();
    let mut metadata = std::collections::HashMap::new();

    for (name, server) in &config.servers {
        let spec = BackendSpec::from_config(name, server);
        let registry = SessionRegistry::new();
        let backend = Backend::new(spec, registry);
        if server.start == Start::Eager {
            match backend.info().await {
                Ok(i) => {
                    tracing::info!(server = %name, protocol = %i.protocol_version, "eager backend started")
                }
                Err(e) => {
                    tracing::error!(server = %name, error = %e, "eager backend failed to start; will retry lazily")
                }
            }
        }

        let ctx = Arc::new(ServerContext {
            name: name.clone(),
            config: server.clone(),
            policy: policy.clone(),
            auth_disabled: config.auth.disabled,
            log_arguments: config.logging.log_arguments,
            shared_backend: backend,
        });

        let mut http_cfg =
            StreamableHttpServerConfig::default().with_cancellation_token(cancel.child_token());
        http_cfg = if disable_host_check {
            http_cfg.disable_allowed_hosts()
        } else {
            http_cfg.with_allowed_hosts(allowed_hosts.clone())
        };
        if !config.listen.allowed_origins.is_empty() {
            http_cfg = http_cfg.with_allowed_origins(config.listen.allowed_origins.clone());
        }
        let factory_ctx = ctx.clone();
        let service = StreamableHttpService::new(
            move || Ok(factory_ctx.new_handler()),
            Arc::new(LocalSessionManager::default()),
            http_cfg,
        );

        let path = server.path().to_string();
        let md_url = metadata_url(&public_origin, &path);
        let auth_state = Arc::new(AuthLayerState {
            server: name.clone(),
            resource: server.resource().clone(),
            metadata_url: md_url,
            scopes: server.advertised_scopes(&config.auth).to_vec(),
            validator: validator.clone(),
            policy: policy.clone(),
        });

        let mount = Router::new()
            .nest_service(&path, service)
            .route_layer(from_fn_with_state(auth_state, require_auth));
        router = router.merge(mount);
        metadata.insert(
            path.clone(),
            ProtectedResourceMetadata::for_server(&config, name, server),
        );
        servers.push(ctx);
        tracing::info!(server = %name, path = %path, resource = %server.resource(), lifecycle = ?server.lifecycle, "mounted");
    }

    let state = Arc::new(AppState {
        config,
        servers,
        metadata,
    });
    let router = router
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(protected_resource_metadata),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/status", get(status))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    Ok(App {
        router,
        state,
        cancel,
    })
}

async fn protected_resource_metadata(
    State(st): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Response {
    let key = format!("/{}", path.trim_end_matches('/'));
    match st.metadata.get(&key) {
        Some(md) => {
            let mut resp = Json(md.clone()).into_response();
            resp.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("public, max-age=300"),
            );
            resp
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "unknown resource"})),
        )
            .into_response(),
    }
}

#[derive(serde::Serialize)]
struct Status {
    version: &'static str,
    auth: &'static str,
    servers: Vec<ServerStatus>,
}

#[derive(serde::Serialize)]
struct ServerStatus {
    path: String,
    resource: String,
    lifecycle: crate::config::Lifecycle,
    backend: BackendStatus,
}

async fn status(State(st): State<Arc<AppState>>) -> Json<Status> {
    Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        auth: if st.config.auth.disabled {
            "disabled"
        } else {
            "oauth"
        },
        servers: st
            .servers
            .iter()
            .map(|s| ServerStatus {
                path: s.config.path().to_string(),
                resource: s.config.resource().to_string(),
                lifecycle: s.config.lifecycle,
                backend: s.shared_backend.status(),
            })
            .collect(),
    })
}

/// Bind and serve until SIGINT/SIGTERM.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.listen.host, config.listen.port).parse()?;
    let app = build_app(config).await?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, public_url = %app.state.config.public_origin(), "host-my-mcp listening");
    let shutdown_app = app.cancel.clone();
    let backends = app.backends();
    axum::serve(listener, app.router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            shutdown_app.cancel();
            for b in backends {
                b.shutdown();
            }
        })
        .await?;
    // Give children a moment to exit cleanly.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
