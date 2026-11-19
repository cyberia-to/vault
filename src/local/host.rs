use super::{Result, io};
use crate::{
    ActorId, CipherStore, Context, Error, GraphStore, PolicyRef, Replica, RequestId, Revision,
    StoredRevision, VaultId,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub index: u64,
    pub commit: [u8; 32],
}
impl From<Revision> for Anchor {
    fn from(r: Revision) -> Self {
        Self {
            index: r.index,
            commit: r.commit,
        }
    }
}
impl From<Anchor> for Revision {
    fn from(r: Anchor) -> Self {
        Self {
            index: r.index,
            commit: r.commit,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Pending {
    pub request: [u8; 32],
    pub previous: Option<Anchor>,
    pub candidate: Anchor,
}
/// A derived public neuron subject. It is deterministic from the key reference
/// and the root version, so retaining it keeps repeated opens free of durable
/// writes. It holds no key material; a tampered record only makes signing fail,
/// because custody re-checks that the key owns the requested subject.
#[derive(Clone, Serialize, Deserialize)]
pub struct SubjectRecord {
    pub key: [u8; 32],
    pub version: u64,
    pub subject: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicaConfig {
    pub id: [u8; 32],
    pub path: PathBuf,
    pub failure_domain: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    pub format: u8,
    pub vault: [u8; 32],
    pub actor: [u8; 32],
    pub policy: [u8; 32],
    pub anchor: Option<Anchor>,
    pub pending: Option<Pending>,
    pub replicas: Vec<ReplicaConfig>,
    #[serde(default)]
    pub subjects: Vec<SubjectRecord>,
}
impl State {
    pub fn new() -> Result<Self> {
        Ok(Self {
            format: 1,
            vault: VaultId::random()?.0,
            actor: ActorId::random()?.0,
            policy: PolicyRef::random()?.0,
            anchor: None,
            pending: None,
            replicas: vec![],
            subjects: vec![],
        })
    }
    pub fn context(&self) -> Context {
        Context {
            actor: ActorId(self.actor),
            policy: PolicyRef(self.policy),
        }
    }
    pub fn checkpoint(&self) -> Result<Self> {
        if self.anchor.is_none() || self.pending.is_some() {
            return Err("host has no settled checkpoint".into());
        }
        Ok(Self {
            replicas: vec![],
            subjects: vec![],
            ..self.clone()
        })
    }
    pub fn read(path: &Path) -> Result<Self> {
        let s: Self = serde_json::from_slice(&io::read_private(path, 64 * 1024)?)
            .map_err(|_| "invalid host checkpoint")?;
        if s.format != 1 {
            return Err("unsupported host checkpoint".into());
        }
        Ok(s)
    }
}

const SUBJECT_RECORDS: usize = 16;

pub struct Host {
    pub store: Arc<JournaledStore>,
    pub directory: PathBuf,
    _lock: File,
}
impl Host {
    pub fn open(directory: &Path, create: bool) -> Result<Self> {
        if create {
            io::private_dir(directory)?;
        } else {
            io::check_private(directory, true)?;
        }
        let directory = directory.canonicalize()?;
        let lock = io::lock(&directory.join("host.lock"))?;
        let file = directory.join("host.json");
        let state = if create {
            // Missing host metadata is not permission to replace an existing store.
            for entry in std::fs::read_dir(&directory)? {
                if entry?.file_name() != "host.lock" {
                    return Err(
                        "init requires an empty host directory; existing data was preserved".into(),
                    );
                }
            }
            let state = State::new()?;
            io::new_file(&file, &serde_json::to_vec(&state)?)?;
            state
        } else {
            State::read(&file)?
        };
        let database = directory.join("graph");
        io::private_dir(&database)?;
        let graph = GraphStore::open(database)?;
        Ok(Self {
            store: Arc::new(JournaledStore {
                graph,
                state: Mutex::new(state),
                file,
            }),
            directory,
            _lock: lock,
        })
    }
    pub fn state(&self) -> Result<State> {
        Ok(self
            .store
            .state
            .lock()
            .map_err(|_| "host state unavailable")?
            .clone())
    }
    pub fn save(&self, state: State) -> Result<()> {
        let mut current = self
            .store
            .state
            .lock()
            .map_err(|_| "host state unavailable")?;
        io::replace(&self.store.file, &serde_json::to_vec(&state)?)?;
        *current = state;
        Ok(())
    }
    /// The retained subject for this key reference at this root version, if any.
    pub fn subject(&self, key: [u8; 32], version: u64) -> Result<Option<[u8; 32]>> {
        Ok(self
            .state()?
            .subjects
            .iter()
            .find(|s| s.key == key && s.version == version)
            .map(|s| s.subject))
    }
    /// Retains one public subject per key reference, bounded so the host file
    /// stays well inside its read limit.
    pub fn remember_subject(&self, key: [u8; 32], version: u64, subject: [u8; 32]) -> Result<()> {
        let mut state = self.state()?;
        state.subjects.retain(|s| s.key != key);
        state.subjects.push(SubjectRecord {
            key,
            version,
            subject,
        });
        while state.subjects.len() > SUBJECT_RECORDS {
            state.subjects.remove(0);
        }
        self.save(state)
    }
    /// Only a candidate retained before append can advance the checkpoint.
    /// The caller must authenticate the complete chain before `settle`.
    pub fn opening_anchor(&self) -> Result<Revision> {
        let s = self.state()?;
        let id = VaultId(s.vault);
        let head = self.store.head(id)?;
        let Some(pending) = s.pending else {
            let anchor = s.anchor.ok_or("initial creation did not commit")?;
            if head != Some(anchor.into()) {
                return Err(Error::StaleAnchor.into());
            }
            return Ok(anchor.into());
        };
        if pending.previous != s.anchor {
            return Err(Error::Corrupt.into());
        }
        let resolved = self.store.resolve(id, RequestId(pending.request))?;
        if resolved == Some(pending.candidate.into()) && head == resolved {
            Ok(pending.candidate.into())
        } else if resolved.is_none() && head == pending.previous.map(Into::into) {
            pending
                .previous
                .map(Into::into)
                .ok_or_else(|| "initial creation did not commit".into())
        } else {
            Err(Error::CommitUnknown.into())
        }
    }
    pub fn settle(&self, revision: Revision) -> Result<()> {
        let mut state = self.state()?;
        if self.opening_anchor()? != revision {
            return Err(Error::StaleAnchor.into());
        }
        state.anchor = Some(revision.into());
        state.pending = None;
        self.save(state)
    }
}

/// Ciphertext stays in Cybergraph. This sidecar retains only trusted host anchors.
pub struct JournaledStore {
    graph: GraphStore,
    state: Mutex<State>,
    file: PathBuf,
}
impl CipherStore for JournaledStore {
    fn head(&self, id: VaultId) -> crate::Result<Option<Revision>> {
        self.graph.head(id)
    }
    fn read(&self, r: Revision) -> crate::Result<StoredRevision> {
        self.graph.read(r)
    }
    fn history_page(
        &self,
        id: VaultId,
        after: Option<u64>,
        limit: usize,
    ) -> crate::Result<Vec<Revision>> {
        self.graph.history_page(id, after, limit)
    }
    fn resolve(&self, id: VaultId, request: RequestId) -> crate::Result<Option<Revision>> {
        self.graph.resolve(id, request)
    }
    fn append(
        &self,
        id: VaultId,
        request: RequestId,
        previous: Option<Revision>,
        bytes: Vec<u8>,
    ) -> crate::Result<Revision> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        if state.vault != id.0
            || state.anchor.map(Into::into) != previous
            || state.pending.is_some()
        {
            return Err(Error::Conflict);
        }
        let index = match previous {
            Some(r) => r.index.checked_add(1).ok_or(Error::Exhausted)?,
            None => 0,
        };
        let candidate = Anchor {
            index,
            commit: *hemera::hash(&bytes).as_bytes(),
        };
        let mut next = state.clone();
        next.pending = Some(Pending {
            request: request.0,
            previous: previous.map(Into::into),
            candidate,
        });
        io::replace(
            &self.file,
            &serde_json::to_vec(&next).map_err(|_| Error::Storage)?,
        )
        .map_err(|_| Error::Storage)?;
        *state = next;
        self.graph.append(id, request, previous, bytes)
    }
}

pub fn replicas(host: &Host) -> Result<Vec<Replica<GraphStore>>> {
    let state = host.state()?;
    if state.replicas.len() < 2 {
        return Err(Error::ReplicationRequired.into());
    }
    state
        .replicas
        .into_iter()
        .map(|r| {
            io::check_private(&r.path, true)?;
            if r.path.canonicalize()? != r.path {
                return Err("replica path changed".into());
            }
            Ok(Replica {
                id: r.id,
                failure_domain: r.failure_domain,
                store: GraphStore::open(r.path)?,
            })
        })
        .collect()
}
