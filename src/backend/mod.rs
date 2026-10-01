//! Backend process supervision: spawn a stdio MCP server as a child process,
//! speak MCP to it through rmcp's client side, restart it within a bounded
//! budget when it dies, and route its server-initiated notifications to the
//! right gateway sessions.

pub mod client;

use std::{
    collections::VecDeque,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use rmcp::{
    RoleClient,
    model::ServerPeerInfo,
    service::{Peer, serve_client_with_ct},
    transport::TokioChildProcess,
};
use tokio_util::sync::CancellationToken;
use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};

use crate::{
    bridge::registry::SessionRegistry,
    config::{Restart, Server},
};
use client::BackendClient;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend `{0}` failed to start: {1}")]
    Spawn(String, String),
    #[error("backend `{0}` is in cooldown after too many restarts")]
    Cooldown(String),
    #[error("backend `{0}` initialize failed: {1}")]
    Initialize(String, String),
    #[error("backend `{0}` initialize timed out")]
    InitializeTimeout(String),
}

#[derive(Debug, Clone)]
pub struct BackendSpec {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<std::path::PathBuf>,
    pub restart: Restart,
    pub request_timeout: Duration,
    pub init_timeout: Duration,
}

impl BackendSpec {
    pub fn from_config(name: &str, s: &Server) -> Self {
        Self {
            name: name.to_string(),
            command: s.command.clone(),
            args: s.args.clone(),
            env: s.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            cwd: s.cwd.clone(),
            restart: s.restart.clone(),
            request_timeout: Duration::from_secs(s.request_timeout_secs),
            init_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
struct Running {
    generation: u64,
    peer: Peer<RoleClient>,
    ct: CancellationToken,
    info: Arc<ServerPeerInfo>,
    pid: Option<u32>,
    started_at: Instant,
}

#[derive(Default)]
struct Inner {
    running: Option<Running>,
    generation: u64,
    spawns: VecDeque<Instant>,
    failed_until: Option<Instant>,
    last_exit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendStatus {
    pub name: String,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    pub restarts_in_window: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<String>,
    pub sessions: usize,
}

/// One supervised stdio MCP backend.
pub struct Backend {
    spec: BackendSpec,
    registry: Arc<SessionRegistry>,
    inner: StdMutex<Inner>,
    spawn_lock: Mutex<()>,
}

impl Backend {
    pub fn new(spec: BackendSpec, registry: Arc<SessionRegistry>) -> Arc<Self> {
        Arc::new(Self { spec, registry, inner: StdMutex::new(Inner::default()), spawn_lock: Mutex::new(()) })
    }

    pub fn name(&self) -> &str {
        &self.spec.name
    }

    pub fn spec(&self) -> &BackendSpec {
        &self.spec
    }

    pub fn registry(&self) -> &Arc<SessionRegistry> {
        &self.registry
    }

    fn current(&self) -> Option<Running> {
        let mut inner = self.inner.lock().expect("backend state poisoned");
        if let Some(r) = &inner.running {
            if r.peer.is_transport_closed() || r.ct.is_cancelled() {
                inner.running = None;
            } else {
                return Some(r.clone());
            }
        }
        None
    }

    /// Obtain a live client peer, spawning (or restarting) the process if needed.
    pub async fn peer(self: &Arc<Self>) -> Result<Peer<RoleClient>, BackendError> {
        Ok(self.ensure_running().await?.peer)
    }

    /// The backend's `initialize` result (capabilities, instructions, server info).
    pub async fn info(self: &Arc<Self>) -> Result<Arc<ServerPeerInfo>, BackendError> {
        Ok(self.ensure_running().await?.info)
    }

    async fn ensure_running(self: &Arc<Self>) -> Result<Running, BackendError> {
        if let Some(r) = self.current() {
            return Ok(r);
        }
        let _guard = self.spawn_lock.lock().await;
        if let Some(r) = self.current() {
            return Ok(r);
        }
        self.check_budget()?;
        let running = self.spawn().await?;
        let mut inner = self.inner.lock().expect("backend state poisoned");
        inner.running = Some(running.clone());
        Ok(running)
    }

    fn check_budget(&self) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("backend state poisoned");
        let now = Instant::now();
        if let Some(until) = inner.failed_until {
            if now < until {
                return Err(BackendError::Cooldown(self.spec.name.clone()));
            }
            inner.failed_until = None;
            inner.spawns.clear();
        }
        let window = Duration::from_secs(self.spec.restart.window_secs);
        while let Some(front) = inner.spawns.front() {
            if now.duration_since(*front) > window {
                inner.spawns.pop_front();
            } else {
                break;
            }
        }
        // The first spawn in a window is a start, the rest are restarts.
        if inner.spawns.len() > self.spec.restart.max_restarts as usize {
            inner.failed_until = Some(now + Duration::from_secs(self.spec.restart.cooldown_secs));
            tracing::error!(
                backend = %self.spec.name,
                restarts = inner.spawns.len() - 1,
                window_secs = self.spec.restart.window_secs,
                cooldown_secs = self.spec.restart.cooldown_secs,
                "restart budget exhausted; backend marked failed"
            );
            return Err(BackendError::Cooldown(self.spec.name.clone()));
        }
        inner.spawns.push_back(now);
        Ok(())
    }

    async fn spawn(self: &Arc<Self>) -> Result<Running, BackendError> {
        let name = self.spec.name.clone();
        let generation = {
            let mut inner = self.inner.lock().expect("backend state poisoned");
            inner.generation += 1;
            inner.generation
        };
        tracing::info!(backend = %name, command = %self.spec.command, generation, "spawning backend");

        let mut cmd = tokio::process::Command::new(&self.spec.command);
        cmd.args(&self.spec.args);
        for (k, v) in &self.spec.env {
            cmd.env(k, v);
        }
        if let Some(cwd) = &self.spec.cwd {
            cmd.current_dir(cwd);
        }
        cmd.kill_on_drop(true);

        let (process, stderr) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError::Spawn(name.clone(), e.to_string()))?;
        let pid = process.id();

        if let Some(stderr) = stderr {
            let log_name = name.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!(target: "backend", backend = %log_name, pid, "{line}");
                }
            });
        }

        let handler = BackendClient::new(name.clone(), self.registry.clone());
        let ct = CancellationToken::new();
        let running = tokio::time::timeout(self.spec.init_timeout, serve_client_with_ct(handler, process, ct.clone()))
            .await
            .map_err(|_| BackendError::InitializeTimeout(name.clone()))?
            .map_err(|e| BackendError::Initialize(name.clone(), e.to_string()))?;

        let peer = running.peer().clone();
        let info = peer
            .peer_info()
            .ok_or_else(|| BackendError::Initialize(name.clone(), "no initialize result".into()))?;
        tracing::info!(
            backend = %name,
            pid,
            server = info.server_info.as_ref().map(|s| s.name.as_str()).unwrap_or("?"),
            version = info.server_info.as_ref().map(|s| s.version.as_str()).unwrap_or("?"),
            protocol = %info.protocol_version,
            "backend ready"
        );

        // Watch for exit and clear state so the next call restarts it.
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let reason = match running.waiting().await {
                Ok(r) => format!("{r:?}"),
                Err(e) => format!("join error: {e}"),
            };
            tracing::warn!(backend = %this.spec.name, pid, generation, reason = %reason, "backend exited");
            let mut inner = this.inner.lock().expect("backend state poisoned");
            if inner.running.as_ref().is_some_and(|r| r.generation == generation) {
                inner.running = None;
            }
            inner.last_exit = Some(reason);
        });

        Ok(Running { generation, peer, ct, info, pid, started_at: Instant::now() })
    }

    pub fn status(&self) -> BackendStatus {
        let inner = self.inner.lock().expect("backend state poisoned");
        let now = Instant::now();
        let (state, pid, uptime) = match &inner.running {
            Some(r) if !r.peer.is_transport_closed() && !r.ct.is_cancelled() => {
                ("running", r.pid, Some(now.duration_since(r.started_at).as_secs()))
            }
            _ if inner.failed_until.is_some_and(|u| now < u) => ("failed", None, None),
            _ => ("stopped", None, None),
        };
        BackendStatus {
            name: self.spec.name.clone(),
            state,
            pid,
            uptime_secs: uptime,
            restarts_in_window: inner.spawns.len().saturating_sub(1),
            last_exit: inner.last_exit.clone(),
            sessions: self.registry.session_count(),
        }
    }

    /// Stop the child. Safe to call from `Drop` (no await).
    pub fn shutdown(&self) {
        let running = self.inner.lock().expect("backend state poisoned").running.take();
        if let Some(r) = running {
            tracing::info!(backend = %self.spec.name, pid = r.pid, "stopping backend");
            r.ct.cancel();
        }
    }
}
