//! Per-backend registry of live MCP sessions and in-flight progress routes.
//!
//! Server-initiated notifications from a shared backend must only reach the
//! sessions they belong to. List-changed and logging notifications fan out to
//! every session; progress notifications are routed by the backend-side
//! progress token to exactly one session, translated back to the token the
//! client originally supplied.

use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rmcp::{RoleServer, model::ProgressToken, service::Peer};

#[derive(Clone)]
pub struct ProgressRoute {
    pub peer: Peer<RoleServer>,
    pub client_token: ProgressToken,
}

#[derive(Default)]
pub struct SessionRegistry {
    next_id: AtomicU64,
    sessions: RwLock<HashMap<u64, Peer<RoleServer>>>,
    progress: RwLock<HashMap<ProgressToken, ProgressRoute>>,
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn register_session(&self, peer: Peer<RoleServer>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.sessions
            .write()
            .expect("registry poisoned")
            .insert(id, peer);
        id
    }

    pub fn unregister_session(&self, id: u64) {
        self.sessions
            .write()
            .expect("registry poisoned")
            .remove(&id);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().expect("registry poisoned").len()
    }

    /// Live session peers, skipping ones whose transport has closed.
    pub fn peers(&self) -> Vec<Peer<RoleServer>> {
        self.sessions
            .read()
            .expect("registry poisoned")
            .values()
            .filter(|p| !p.is_transport_closed())
            .cloned()
            .collect()
    }

    pub fn register_progress(&self, backend_token: ProgressToken, route: ProgressRoute) {
        self.progress
            .write()
            .expect("registry poisoned")
            .insert(backend_token, route);
    }

    pub fn unregister_progress(&self, backend_token: &ProgressToken) {
        self.progress
            .write()
            .expect("registry poisoned")
            .remove(backend_token);
    }

    pub fn route_progress(&self, backend_token: &ProgressToken) -> Option<ProgressRoute> {
        self.progress
            .read()
            .expect("registry poisoned")
            .get(backend_token)
            .cloned()
    }
}
