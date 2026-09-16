#![allow(dead_code)]
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU8, Ordering},
};
use tempfile::TempDir;
use vault::*;
use zeroize::Zeroizing;

pub const PASSWORD: &[u8] = b"synthetic-unlock-passphrase";
pub const RECOVERY: [u8; 32] = [9; 32];
pub fn context() -> Context {
    Context {
        actor: ActorId([1; 32]),
        policy: PolicyRef([2; 32]),
    }
}
pub fn request() -> RequestId {
    RequestId::random().unwrap()
}

pub struct TestWard {
    pub state: RwLock<(bool, u64)>,
}
impl TestWard {
    pub fn new() -> Self {
        Self {
            state: RwLock::new((true, 59)),
        }
    }
}
impl Ward for TestWard {
    fn with_authorization<T>(
        &self,
        intent: &Intent,
        action: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        let guard = self.state.read().map_err(|_| Error::Denied)?;
        if !guard.0 || intent.context != context() {
            return Err(Error::Denied);
        }
        action(guard.1)
    }
}
pub struct FaultStore {
    pub graph: GraphStore,
    pub fault: AtomicU8,
}
impl FaultStore {
    pub fn open(path: &std::path::Path) -> Self {
        Self {
            graph: GraphStore::open(path).unwrap(),
            fault: AtomicU8::new(0),
        }
    }
}
impl CipherStore for FaultStore {
    fn head(&self, id: VaultId) -> Result<Option<Revision>> {
        self.graph.head(id)
    }
    fn read(&self, r: Revision) -> Result<StoredRevision> {
        let mut value = self.graph.read(r)?;
        if self.fault.load(Ordering::SeqCst) == 3 {
            value.bytes[0] ^= 1;
        }
        Ok(value)
    }
    fn history_page(&self, id: VaultId, after: Option<u64>, limit: usize) -> Result<Vec<Revision>> {
        let mut values = self.graph.history_page(id, after, limit)?;
        if self.fault.load(Ordering::SeqCst) == 4 {
            values.pop();
        }
        if after == Some(4095) {
            match self.fault.load(Ordering::SeqCst) {
                6 if !values.is_empty() => {
                    values.remove(0);
                }
                7 => values.clear(),
                _ => {}
            }
        }
        Ok(values)
    }
    fn resolve(&self, id: VaultId, req: RequestId) -> Result<Option<Revision>> {
        self.graph.resolve(id, req)
    }
    fn append(
        &self,
        id: VaultId,
        req: RequestId,
        expected: Option<Revision>,
        bytes: Vec<u8>,
    ) -> Result<Revision> {
        let fault = self.fault.swap(0, Ordering::SeqCst);
        if fault == 1 {
            return Err(Error::Storage);
        }
        if fault == 5 {
            // A faulty provider acknowledges a packet without retaining it.
            return Ok(Revision {
                index: expected.map_or(0, |r| r.index + 1),
                commit: *hemera::hash(&bytes).as_bytes(),
            });
        }
        let result = self.graph.append(id, req, expected, bytes)?;
        if fault == 2 {
            return Err(Error::CommitUnknown);
        }
        Ok(result)
    }
}
pub struct Fixture {
    pub directory: TempDir,
    pub store: Arc<FaultStore>,
    pub vault: Vault<Arc<FaultStore>>,
    pub ward: TestWard,
    pub replicas: Vec<Replica<GraphStore>>,
}
impl Fixture {
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ward = TestWard::new();
        let store = Arc::new(FaultStore::open(&directory.path().join("primary")));
        let vault = Vault::create(
            store.clone(),
            VaultId::random().unwrap(),
            request(),
            context(),
            PASSWORD,
            &RECOVERY,
            &ward,
        )
        .unwrap();
        let replicas = vec![
            Replica {
                id: [3; 32],
                failure_domain: "a".into(),
                store: GraphStore::open(directory.path().join("a")).unwrap(),
            },
            Replica {
                id: [4; 32],
                failure_domain: "b".into(),
                store: GraphStore::open(directory.path().join("b")).unwrap(),
            },
        ];
        Self {
            directory,
            store,
            vault,
            ward,
            replicas,
        }
    }
    pub fn put(&mut self, input: SecretInput, revealable: bool) -> SecretRef {
        let id = SecretRef::random().unwrap();
        self.vault
            .put(
                context(),
                request(),
                entry(id, input, revealable),
                None,
                &self.ward,
            )
            .unwrap();
        id
    }
    pub fn use_bytes(&mut self, operation: Operation) -> Zeroizing<Vec<u8>> {
        let pending = self
            .vault
            .prepare_use(context(), request(), operation, &self.ward)
            .unwrap();
        let copies = self.vault.replicate(&self.replicas).unwrap();
        self.vault
            .release(context(), &pending, &copies, &self.ward, |out| match out {
                Output::Secret(value) => Ok(value),
                _ => Err(Error::Corrupt),
            })
            .unwrap()
    }
}
pub fn entry(id: SecretRef, input: SecretInput, revealable: bool) -> Entry {
    Entry::new(
        id,
        "synthetic private label".into(),
        "https://example.invalid".into(),
        context().policy,
        revealable,
        input,
    )
    .unwrap()
}
pub fn password(value: &[u8]) -> SecretInput {
    SecretInput::password(Zeroizing::new(value.to_vec())).unwrap()
}
