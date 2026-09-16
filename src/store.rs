use crate::{Error, RequestId, Result, Revision, VaultId};

/// Ciphertext only. Implementations must enforce CAS, exact retry and durability.
pub trait CipherStore {
    fn head(&self, vault: VaultId) -> Result<Option<Revision>>;
    fn read(&self, revision: Revision) -> Result<StoredRevision>;
    /// Ascending rows strictly after `after`. Empty means the end; short pages
    /// are allowed. The limit bounds this read, never the total history.
    fn history_page(
        &self,
        vault: VaultId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Revision>>;
    /// Convenience collector. Custody/recovery/replication stream pages instead.
    fn history(&self, vault: VaultId) -> Result<Vec<Revision>>
    where
        Self: Sized,
    {
        let Some(anchor) = self.head(vault)? else {
            return Ok(Vec::new());
        };
        let mut rows = Vec::new();
        crate::history::walk(self, vault, anchor, |r, _| {
            rows.push(r);
            Ok(())
        })?;
        Ok(rows)
    }
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
    fn history_page(
        &self,
        vault: VaultId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Revision>> {
        (**self).history_page(vault, after, limit)
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
