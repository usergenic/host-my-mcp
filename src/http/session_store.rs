//! A durable [`SessionStore`] so MCP sessions survive a gateway restart.
//!
//! rmcp drops its in-memory session map when the process exits (and idle-kills
//! individual workers while running). With a session store configured, rmcp
//! persists the client's `initialize` parameters after each successful
//! handshake and, when a request later arrives for a session it no longer holds
//! in memory, transparently re-creates the session by replaying that
//! handshake — so the client never has to re-initialize and the backend is
//! re-bridged automatically. Only the small, serializable handshake parameters
//! are stored; no live transport or child-process state is (nor could be).
//!
//! This implementation keeps the `session_id -> SessionState` map in memory and
//! mirrors it to a JSON file (atomic rename, `0600` on Unix) so recovery works
//! across a restart without pulling in a database.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use async_trait::async_trait;
use rmcp::transport::streamable_http_server::session::store::{
    SessionState, SessionStore, SessionStoreError,
};

pub struct FileSessionStore {
    path: PathBuf,
    sessions: Mutex<BTreeMap<String, SessionState>>,
}

impl FileSessionStore {
    /// Open (or create) the store at `path`, creating the parent directory if
    /// needed. A corrupt or unreadable file is logged and treated as empty
    /// rather than blocking startup: session recovery is best-effort, and a
    /// client can always re-initialize.
    pub fn open(path: PathBuf) -> Self {
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(dir = %parent.display(), error = %e, "cannot create session store dir");
        }
        let sessions = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!(path = %path.display(), error = %e, "session store is unreadable; starting empty");
                BTreeMap::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read session store; starting empty");
                BTreeMap::new()
            }
        };
        Self {
            path,
            sessions: Mutex::new(sessions),
        }
    }

    fn persist(&self, sessions: &BTreeMap<String, SessionState>) {
        if let Err(e) = write_atomic(&self.path, sessions) {
            tracing::error!(path = %self.path.display(), error = %e, "could not persist session store");
        }
    }
}

#[async_trait]
impl SessionStore for FileSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        Ok(self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(session_id)
            .cloned())
    }

    async fn store(&self, session_id: &str, state: &SessionState) -> Result<(), SessionStoreError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.insert(session_id.to_string(), state.clone());
        self.persist(&sessions);
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if sessions.remove(session_id).is_some() {
            self.persist(&sessions);
        }
        Ok(())
    }
}

fn write_atomic(path: &Path, value: &BTreeMap<String, SessionState>) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::InitializeRequestParams;

    fn state() -> SessionState {
        SessionState::new(InitializeRequestParams::default())
    }

    #[tokio::test]
    async fn persists_and_reloads_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions-x.json");

        let store = FileSessionStore::open(path.clone());
        assert!(store.load("s1").await.unwrap().is_none());
        store.store("s1", &state()).await.unwrap();
        assert!(store.load("s1").await.unwrap().is_some());

        // A fresh store at the same path (simulating a gateway restart) still
        // finds the session.
        let reopened = FileSessionStore::open(path.clone());
        assert!(reopened.load("s1").await.unwrap().is_some());

        // Delete removes it, and the removal survives another reopen.
        reopened.delete("s1").await.unwrap();
        assert!(reopened.load("s1").await.unwrap().is_none());
        let again = FileSessionStore::open(path);
        assert!(again.load("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unreadable_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions-bad.json");
        std::fs::write(&path, b"not json").unwrap();
        let store = FileSessionStore::open(path);
        assert!(store.load("anything").await.unwrap().is_none());
    }
}
