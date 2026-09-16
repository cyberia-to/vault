use crate::{
    CipherStore, Error, MAX_REVISIONS, Result, Revision, VaultId, custody::load_packet,
    store::checked,
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
    history: Vec<Revision>,
    replicas: Vec<([u8; 32], String)>,
}
impl CopyEvidence {
    pub fn revision(&self) -> Revision {
        self.history[self.history.len() - 1]
    }
    pub fn copies(&self) -> usize {
        self.replicas.len()
    }
    pub(crate) fn covers(&self, vault: VaultId, head: Revision) -> bool {
        self.vault == vault
            && self.replicas.len() >= 2
            && self.history.get(head.index as usize) == Some(&head)
    }
}
pub(crate) fn chain<S: CipherStore>(
    store: &S,
    vault: VaultId,
    anchor: Revision,
) -> Result<Vec<Revision>> {
    if anchor.index >= MAX_REVISIONS {
        return Err(Error::Limit);
    }
    if store.head(vault)? != Some(anchor) {
        return Err(Error::StaleAnchor);
    }
    let history = store.history(vault)?;
    if history.len() != anchor.index as usize + 1 || history.last() != Some(&anchor) {
        return Err(Error::Corrupt);
    }
    let mut previous = None;
    let mut header = None;
    for (i, r) in history.iter().enumerate() {
        if r.index != i as u64 {
            return Err(Error::Corrupt);
        }
        let packet = load_packet(store, *r)?;
        if packet.header.vault != vault || packet.previous != previous {
            return Err(Error::Corrupt);
        }
        if header.as_ref().is_some_and(|h| *h != packet.header) {
            return Err(Error::Corrupt);
        }
        if store.resolve(vault, packet.request)? != Some(*r) {
            return Err(Error::Corrupt);
        }
        header = Some(packet.header);
        previous = Some(*r);
    }
    Ok(history)
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
    let history = chain(source, vault, anchor)?;
    for replica in replicas {
        let mut current = replica.store.head(vault)?;
        if let Some(head) = current {
            let existing = chain(&replica.store, vault, head)?;
            if existing.len() > history.len() || existing != history[..existing.len()] {
                return Err(Error::Conflict);
            }
        }
        let start = current.map_or(0, |h| h.index as usize + 1);
        for r in &history[start..] {
            let packet = load_packet(source, *r)?;
            let bytes = checked(source.read(*r)?, *r)?.bytes;
            let received = replica
                .store
                .append(vault, packet.request, current, bytes)?;
            if received != *r {
                return Err(Error::Corrupt);
            }
            current = Some(received);
        }
        // Re-open/ack semantics belong to the store; readback verifies the full closure.
        if chain(&replica.store, vault, anchor)? != history {
            return Err(Error::Corrupt);
        }
    }
    if source.head(vault)? != Some(anchor) {
        return Err(Error::StaleAnchor);
    }
    Ok(CopyEvidence {
        vault,
        history,
        replicas: replicas
            .iter()
            .map(|r| (r.id, r.failure_domain.clone()))
            .collect(),
    })
}
