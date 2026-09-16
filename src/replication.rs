use crate::{
    CipherStore, Error, Result, Revision, VaultId,
    history::{at, walk},
};
use std::collections::BTreeSet;

pub struct Replica<S: CipherStore> {
    pub id: [u8; 32],
    pub failure_domain: String,
    pub store: S,
}
/// Readback-verified local copies; not remote receipt authentication or proof
/// that the configured failure-domain labels represent independent hardware.
#[derive(Debug)]
pub struct CopyEvidence {
    vault: VaultId,
    anchor: Revision,
    replicas: Vec<([u8; 32], String)>,
}
impl CopyEvidence {
    pub fn revision(&self) -> Revision {
        self.anchor
    }
    pub fn copies(&self) -> usize {
        self.replicas.len()
    }
    pub(crate) fn covers<S: CipherStore>(
        &self,
        store: &S,
        vault: VaultId,
        head: Revision,
    ) -> Result<bool> {
        Ok(self.vault == vault
            && self.replicas.len() >= 2
            && head.index <= self.anchor.index
            && at(store, vault, self.anchor.index)? == Some(self.anchor)
            && at(store, vault, head.index)? == Some(head))
    }
}
pub(crate) fn replicate<S: CipherStore, T: CipherStore>(
    source: &S,
    vault: VaultId,
    anchor: Revision,
    replicas: &[Replica<T>],
) -> Result<CopyEvidence> {
    if replicas.len() < 2 || replicas.len() > 8 {
        return Err(Error::ReplicationRequired);
    }
    let mut domains = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for r in replicas {
        if r.failure_domain.is_empty()
            || r.failure_domain.len() > 256
            || !domains.insert(&r.failure_domain)
            || !ids.insert(r.id)
        {
            return Err(Error::InvalidInput);
        }
    }
    walk(source, vault, anchor, |_, _| Ok(()))?;
    for replica in replicas {
        let mut current = replica.store.head(vault)?;
        if let Some(head) = current {
            if head.index > anchor.index || at(source, vault, head.index)? != Some(head) {
                return Err(Error::Conflict);
            }
            walk(&replica.store, vault, head, |_, _| Ok(()))?;
        }
        let initial = current;
        walk(source, vault, anchor, |r, packet| {
            if initial.is_some_and(|h| r.index <= h.index) {
                return Ok(());
            }
            let received =
                replica
                    .store
                    .append(vault, packet.request, current, packet.encode()?)?;
            if received != r {
                return Err(Error::Corrupt);
            }
            current = Some(received);
            Ok(())
        })?;
        walk(&replica.store, vault, anchor, |_, _| Ok(()))?;
    }
    if source.head(vault)? != Some(anchor) {
        return Err(Error::StaleAnchor);
    }
    Ok(CopyEvidence {
        vault,
        anchor,
        replicas: replicas
            .iter()
            .map(|r| (r.id, r.failure_domain.clone()))
            .collect(),
    })
}
