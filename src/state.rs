pub(crate) mod catalog;
pub(crate) mod legacy;

use crate::{
    ActorId, Context, Entry, Error, PolicyRef, RequestId, Result, SecretRef,
    codec::{Decoder, Encoder},
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub(crate) struct Record {
    pub request: RequestId,
    pub fingerprint: [u8; 32],
    pub receipt: Receipt,
    pub change: Change,
}
pub(crate) enum Change {
    Genesis,
    Put(Box<Entry>),
    Delete(SecretRef),
    Use(Box<Entry>),
    Legacy(Box<LegacyCatalog>),
}
pub(crate) struct LegacyCatalog {
    pub entries: BTreeMap<SecretRef, Entry>,
    pub deleted: BTreeSet<SecretRef>,
}
pub(crate) struct Receipt {
    pub context: Context,
    pub secret: Option<SecretRef>,
    pub entry_version: u64,
    pub operation: Zeroizing<Vec<u8>>,
    pub output: Zeroizing<Vec<u8>>,
}
impl Record {
    pub fn genesis(request: RequestId, context: Context) -> Self {
        Self {
            request,
            fingerprint: [0; 32],
            change: Change::Genesis,
            receipt: Receipt {
                context,
                secret: None,
                entry_version: 0,
                operation: Zeroizing::new(vec![]),
                output: Zeroizing::new(vec![]),
            },
        }
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new();
        e.fixed(b"VSTATE2");
        e.fixed(&self.request.0);
        e.fixed(&self.fingerprint);
        e.fixed(&self.receipt.context.actor.0);
        e.fixed(&self.receipt.context.policy.0);
        match self.receipt.secret {
            Some(id) => {
                e.byte(1);
                e.fixed(&id.0);
            }
            None => e.byte(0),
        }
        e.u64(self.receipt.entry_version);
        e.bytes(&self.receipt.operation)?;
        e.bytes(&self.receipt.output)?;
        match &self.change {
            Change::Genesis => e.byte(0),
            Change::Put(entry) => {
                e.byte(1);
                entry.encode(&mut e)?;
            }
            Change::Delete(id) => {
                e.byte(2);
                e.fixed(&id.0);
            }
            Change::Use(entry) => {
                e.byte(3);
                entry.encode(&mut e)?;
            }
            Change::Legacy(_) => return Err(Error::Unsupported),
        }
        Ok(e.0)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"VSTATE1") {
            let old = legacy::Snapshot::decode(bytes)?;
            return Ok(Self {
                request: old.request,
                fingerprint: old.fingerprint,
                receipt: old.receipt,
                change: Change::Legacy(Box::new(LegacyCatalog {
                    entries: old.entries,
                    deleted: old.deleted,
                })),
            });
        }
        let mut d = Decoder::new(bytes)?;
        if d.take(7)? != b"VSTATE2" {
            return Err(Error::Unsupported);
        }
        let request = RequestId(d.array()?);
        let fingerprint = d.array()?;
        let context = Context {
            actor: ActorId(d.array()?),
            policy: PolicyRef(d.array()?),
        };
        let secret = match d.byte()? {
            0 => None,
            1 => Some(SecretRef(d.array()?)),
            _ => return Err(Error::Corrupt),
        };
        let entry_version = d.u64()?;
        let operation = Zeroizing::new(d.bytes(65536)?.to_vec());
        let output = Zeroizing::new(d.bytes(32768)?.to_vec());
        let change = match d.byte()? {
            0 => Change::Genesis,
            1 => Change::Put(Box::new(Entry::decode(&mut d)?)),
            2 => Change::Delete(SecretRef(d.array()?)),
            3 => Change::Use(Box::new(Entry::decode(&mut d)?)),
            _ => return Err(Error::Unsupported),
        };
        d.finish()?;
        Ok(Self {
            request,
            fingerprint,
            change,
            receipt: Receipt {
                context,
                secret,
                entry_version,
                operation,
                output,
            },
        })
    }
    pub fn take_entry(self, id: SecretRef) -> Result<Entry> {
        match self.change {
            Change::Put(entry) | Change::Use(entry) if entry.info.id == id => Ok(*entry),
            Change::Legacy(mut old) => old.entries.remove(&id).ok_or(Error::Corrupt),
            _ => Err(Error::Corrupt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v2_genesis_has_a_fixed_encoding_and_rejects_truncation_and_extra_bytes() {
        let record = Record::genesis(
            RequestId([0x11; 32]),
            Context {
                actor: ActorId([0x22; 32]),
                policy: PolicyRef([0x33; 32]),
            },
        );
        let mut expected = b"VSTATE2".to_vec();
        expected.extend([0x11; 32]);
        expected.extend([0; 32]);
        expected.extend([0x22; 32]);
        expected.extend([0x33; 32]);
        expected.extend([0; 18]);
        assert_eq!(record.encode().unwrap().as_slice(), expected);
        assert_eq!(
            Record::decode(&expected)
                .unwrap()
                .encode()
                .unwrap()
                .as_slice(),
            expected
        );
        for end in 0..expected.len() {
            assert!(Record::decode(&expected[..end]).is_err());
        }
        expected.push(0);
        assert!(Record::decode(&expected).is_err());
    }
}
