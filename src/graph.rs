use crate::{
    CipherStore, Error, MAX_REVISIONS, MAX_SNAPSHOT_BYTES, RequestId, Result, Revision,
    StoredRevision, VaultId,
};
use cybergraph::{
    application::{ApplicationGraph, Database, Error as GraphError, Head, Proposal, StorageError},
    content::{Codec, Content},
};
use std::path::Path;

/// Existing Cybergraph application path over one BBG Database owner.
pub struct GraphStore(ApplicationGraph);
impl GraphStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self(ApplicationGraph::open(path).map_err(map)?))
    }
    pub fn from_database(database: Database) -> Self {
        Self(ApplicationGraph::from_database(database))
    }
}
fn head(r: Revision) -> Head {
    Head {
        index: r.index,
        commit: r.commit,
    }
}
fn revision(h: Head) -> Revision {
    Revision {
        index: h.index,
        commit: h.commit,
    }
}
impl CipherStore for GraphStore {
    fn head(&self, vault: VaultId) -> Result<Option<Revision>> {
        Ok(self.0.head(&vault.0).map_err(map)?.map(revision))
    }
    fn read(&self, r: Revision) -> Result<StoredRevision> {
        let content = self.0.get(&r.commit).map_err(map)?.ok_or(Error::NotFound)?;
        if content.codec() != Codec::Blob || content.bytes().len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Corrupt);
        }
        Ok(StoredRevision {
            revision: r,
            bytes: content.bytes().to_vec(),
        })
    }
    fn history(&self, vault: VaultId) -> Result<Vec<Revision>> {
        let rows = self
            .0
            .history(&vault.0, None, MAX_REVISIONS as usize)
            .map_err(map)?;
        Ok(rows.into_iter().map(revision).collect())
    }
    fn resolve(&self, vault: VaultId, request: RequestId) -> Result<Option<Revision>> {
        Ok(self
            .0
            .resolve(&vault.0, &request.0)
            .map_err(map)?
            .map(revision))
    }
    fn append(
        &self,
        vault: VaultId,
        request: RequestId,
        expected: Option<Revision>,
        bytes: Vec<u8>,
    ) -> Result<Revision> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        let packet = crate::crypto::Packet::decode(&bytes)?;
        if packet.header.vault != vault || packet.previous != expected || packet.request != request
        {
            return Err(Error::Corrupt);
        }
        let content = Content::new(Codec::Blob, bytes).map_err(|_| Error::Corrupt)?;
        let proposal = Proposal {
            namespace: vault.0,
            request: request.0,
            expected: expected.map(head),
            head: Head {
                index: packet.index,
                commit: content.id(),
            },
            content: vec![content],
            required: vec![],
            claims: vec![],
        };
        self.0
            .commit(&proposal, |_| Ok(()))
            .map(revision)
            .map_err(map)
    }
}
fn map(error: GraphError) -> Error {
    match error {
        GraphError::Storage(StorageError::CommitUnknown(_)) => Error::CommitUnknown,
        GraphError::Storage(
            StorageError::HeadMismatch | StorageError::Conflict | StorageError::Fenced,
        ) => Error::Conflict,
        GraphError::Storage(StorageError::Limit) => Error::Limit,
        GraphError::Content(_)
        | GraphError::MissingContent(_)
        | GraphError::InvalidProposal
        | GraphError::Storage(StorageError::Corrupt | StorageError::InvalidSequence) => {
            Error::Corrupt
        }
        _ => Error::Storage,
    }
}
