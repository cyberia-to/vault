use super::{Change, Record};
use crate::{Error, PolicyRef, Result, Revision, SecretKind, SecretRef};
use std::collections::{BTreeMap, BTreeSet};

/// Only an index is retained in memory. Secret payloads stay in encrypted graph
/// packets and are decrypted on demand; no mutation duplicates the catalog.
#[derive(Default)]
pub(crate) struct Catalog {
    pub entries: BTreeMap<SecretRef, Location>,
    pub deleted: BTreeSet<SecretRef>,
    v2_seen: bool,
}
pub(crate) struct Location {
    pub revision: Revision,
    pub version: u64,
    pub kind: SecretKind,
    pub policy: PolicyRef,
}
impl Catalog {
    pub fn validate(&self, record: &Record, head: Revision) -> Result<()> {
        let receipt = &record.receipt;
        match &record.change {
            Change::Genesis => {
                if head.index != 0
                    || !self.entries.is_empty()
                    || !self.deleted.is_empty()
                    || receipt.secret.is_some()
                    || receipt.entry_version != 0
                    || !receipt.operation.is_empty()
                    || !receipt.output.is_empty()
                {
                    return Err(Error::Corrupt);
                }
            }
            Change::Put(entry) => {
                let info = &entry.info;
                if head.index == 0
                    || info.version != head.index
                    || self.deleted.contains(&info.id)
                    || info.policy != receipt.context.policy
                    || receipt.secret.is_some()
                    || !receipt.output.is_empty()
                {
                    return Err(Error::Corrupt);
                }
                if let Some(old) = self.entries.get(&info.id)
                    && (old.kind != info.kind || old.policy != info.policy)
                {
                    return Err(Error::Corrupt);
                }
            }
            Change::Delete(id) => {
                if head.index == 0
                    || !self.entries.contains_key(id)
                    || self.entries[id].policy != receipt.context.policy
                    || receipt.secret.is_some()
                    || !receipt.output.is_empty()
                {
                    return Err(Error::Corrupt);
                }
            }
            Change::Use(entry) => {
                let info = &entry.info;
                let old = self.entries.get(&info.id).ok_or(Error::Corrupt)?;
                if head.index == 0
                    || old.version != info.version
                    || old.kind != info.kind
                    || old.policy != info.policy
                    || info.policy != receipt.context.policy
                    || receipt.secret != Some(info.id)
                    || receipt.entry_version != info.version
                {
                    return Err(Error::Corrupt);
                }
            }
            Change::Legacy(old) => {
                if self.v2_seen
                    || old
                        .entries
                        .values()
                        .any(|e| e.info.version == 0 || e.info.version > head.index)
                {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }
    pub fn apply(&mut self, record: &Record, head: Revision) -> Result<()> {
        self.validate(record, head)?;
        match &record.change {
            Change::Genesis => {}
            Change::Put(entry) | Change::Use(entry) => {
                self.insert(entry, head);
            }
            Change::Delete(id) => {
                self.entries.remove(id);
                self.deleted.insert(*id);
            }
            Change::Legacy(old) => {
                self.entries.clear();
                self.deleted.clone_from(&old.deleted);
                for entry in old.entries.values() {
                    self.insert(entry, head);
                }
            }
        }
        self.v2_seen |= !matches!(record.change, Change::Legacy(_));
        Ok(())
    }
    fn insert(&mut self, entry: &crate::Entry, revision: Revision) {
        let info = &entry.info;
        self.entries.insert(
            info.id,
            Location {
                revision,
                version: info.version,
                kind: info.kind,
                policy: info.policy,
            },
        );
    }
}
