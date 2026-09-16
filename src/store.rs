use crate::{Error, RequestId, Result, Revision, VaultId};

/// Ciphertext only. Implementations must enforce CAS, exact retry and durability.
pub trait CipherStore {
    fn head(&self, vault: VaultId) -> Result<Option<Revision>>;
    fn read(&self, revision: Revision) -> Result<StoredRevision>;
    fn history(&self, vault: VaultId) -> Result<Vec<Revision>>;
    fn resolve(&self, vault: VaultId, request: RequestId) -> Result<Option<Revision>>;
    fn append(
        &self,
        vault: VaultId,
        request: RequestId,
        expected: Option<Revision>,
        bytes: Vec<u8>,
    ) -> Result<Revision>;
}

impl<S: CipherStore + ?Sized> CipherStore for std::sync::Arc<S> {
    fn head(&self, vault: VaultId) -> Result<Option<Revision>> {
        (**self).head(vault)
    }
    fn read(&self, revision: Revision) -> Result<StoredRevision> {
        (**self).read(revision)
    }
    fn history(&self, vault: VaultId) -> Result<Vec<Revision>> {
        (**self).history(vault)
    }
    fn resolve(&self, vault: VaultId, request: RequestId) -> Result<Option<Revision>> {
        (**self).resolve(vault, request)
    }
    fn append(
        &self,
        vault: VaultId,
        request: RequestId,
        expected: Option<Revision>,
        bytes: Vec<u8>,
    ) -> Result<Revision> {
        (**self).append(vault, request, expected, bytes)
    }
}

#[derive(Clone, Debug)]
pub struct StoredRevision {
    pub revision: Revision,
    pub bytes: Vec<u8>,
}

pub(crate) fn identity(bytes: &[u8]) -> [u8; 32] {
    *hemera::hash(bytes).as_bytes()
}
pub(crate) fn checked(value: StoredRevision, expected: Revision) -> Result<StoredRevision> {
    if value.revision != expected || identity(&value.bytes) != expected.commit {
        return Err(Error::Corrupt);
    }
    Ok(value)
}
