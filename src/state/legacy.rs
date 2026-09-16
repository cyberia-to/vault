#[cfg(test)]
use crate::codec::Encoder;
use crate::{
    ActorId, Context, Entry, Error, PolicyRef, RequestId, Result, SecretRef, codec::Decoder,
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub(crate) struct Snapshot {
    pub entries: BTreeMap<SecretRef, Entry>,
    pub deleted: BTreeSet<SecretRef>,
    pub request: RequestId,
    pub fingerprint: [u8; 32],
    pub receipt: Receipt,
}

use super::Receipt;
impl Snapshot {
    #[cfg(all(test, feature = "graph-store"))]
    pub fn empty(request: RequestId, context: Context) -> Self {
        Self {
            entries: BTreeMap::new(),
            deleted: BTreeSet::new(),
            request,
            fingerprint: [0; 32],
            receipt: Receipt {
                context,
                secret: None,
                entry_version: 0,
                operation: Zeroizing::new(vec![]),
                output: Zeroizing::new(vec![]),
            },
        }
    }
    #[cfg(test)]
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new();
        e.fixed(b"VSTATE1");
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
        e.u32(self.entries.len() as u32);
        for entry in self.entries.values() {
            entry.encode(&mut e)?;
        }
        e.u32(self.deleted.len() as u32);
        for id in &self.deleted {
            e.fixed(&id.0);
        }
        Ok(e.0)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes)?;
        if d.take(7)? != b"VSTATE1" {
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
        let count = d.u32()? as usize;
        if count > d.remaining() / 16 {
            return Err(Error::Limit);
        }
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let entry = Entry::decode(&mut d)?;
            if entries
                .last_key_value()
                .is_some_and(|(id, _)| *id >= entry.info.id)
            {
                return Err(Error::Corrupt);
            }
            entries.insert(entry.info.id, entry);
        }
        let count = d.u32()? as usize;
        if count > d.remaining() / 16 {
            return Err(Error::Limit);
        }
        let mut deleted = BTreeSet::new();
        for _ in 0..count {
            let id = SecretRef(d.array()?);
            if deleted.last().is_some_and(|v| *v >= id) || entries.contains_key(&id) {
                return Err(Error::Corrupt);
            }
            deleted.insert(id);
        }
        d.finish()?;
        Ok(Self {
            entries,
            deleted,
            request,
            fingerprint,
            receipt: Receipt {
                context,
                secret,
                entry_version,
                operation,
                output,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_genesis_fixture_rejects_truncation_trailing_and_hostile_counts() {
        // Frozen v1 fixture, assembled independently of Encoder.
        let mut fixture = b"VSTATE1".to_vec();
        fixture.extend([0x11; 32]);
        fixture.extend([0; 32]);
        fixture.extend([0x22; 32]);
        fixture.extend([0x33; 32]);
        fixture.extend([0; 25]);
        assert_eq!(fixture.len(), 160);
        let decoded = Snapshot::decode(&fixture).unwrap();
        assert_eq!(decoded.request, RequestId([0x11; 32]));
        assert_eq!(decoded.encode().unwrap().as_slice(), fixture);
        for end in 0..fixture.len() {
            assert!(Snapshot::decode(&fixture[..end]).is_err());
        }
        let mut trailing = fixture.clone();
        trailing.push(0);
        assert!(Snapshot::decode(&trailing).is_err());
        for offset in [144, 148, 152, 156] {
            let mut hostile = fixture.clone();
            hostile[offset..offset + 4].fill(0xff);
            assert!(Snapshot::decode(&hostile).is_err());
        }
    }
}
