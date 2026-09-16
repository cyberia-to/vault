use super::*;
use crate::state::{Change, Receipt};

impl<S: CipherStore> Vault<S> {
    pub fn put<W: Ward>(
        &mut self,
        context: Context,
        request: RequestId,
        entry: Entry,
        expected_version: Option<u64>,
        ward: &W,
    ) -> Result<Revision> {
        self.ready(true)?;
        entry.validate()?;
        if entry.info.policy != context.policy {
            return Err(Error::Denied);
        }
        let mut e = Encoder::new();
        e.byte(1);
        entry.encode(&mut e)?;
        match expected_version {
            None => e.byte(0),
            Some(v) => {
                e.byte(1);
                e.u64(v);
            }
        }
        let binding = self.binding(context, request, &e.0)?;
        let intent = Intent {
            vault: self.id(),
            request,
            context,
            binding,
            kind: IntentKind::Put {
                entry: entry.info.clone(),
                expected_version,
            },
        };
        ward.with_authorization(&intent, |_| {
            self.current()?;
            if let Some((head, _)) = self.prior(request, binding)? {
                return Ok(head);
            }
            let id = entry.info.id;
            let current = self.state()?.entries.get(&id);
            match (current, expected_version) {
                (None, None) if !self.state()?.deleted.contains(&id) => {}
                (Some(old), Some(v))
                    if old.version == v
                        && old.kind == entry.info.kind
                        && old.policy == context.policy => {}
                _ => return Err(Error::Conflict),
            }
            let mut entry = entry;
            entry.info.version = self.head.index.checked_add(1).ok_or(Error::Limit)?;
            let state = Record {
                request,
                fingerprint: binding,
                change: Change::Put(Box::new(entry)),
                receipt: Receipt {
                    context,
                    secret: None,
                    entry_version: 0,
                    operation: e.0,
                    output: Zeroizing::new(vec![]),
                },
            };
            self.commit(state)
        })
    }
    pub fn delete<W: Ward>(
        &mut self,
        context: Context,
        request: RequestId,
        secret: SecretRef,
        expected_version: u64,
        ward: &W,
    ) -> Result<Revision> {
        self.ready(true)?;
        let mut e = Encoder::new();
        e.byte(2);
        e.fixed(&secret.0);
        e.u64(expected_version);
        let binding = self.binding(context, request, &e.0)?;
        let intent = Intent {
            vault: self.id(),
            request,
            context,
            binding,
            kind: IntentKind::Delete {
                secret,
                expected_version,
            },
        };
        ward.with_authorization(&intent, |_| {
            self.current()?;
            if let Some((head, _)) = self.prior(request, binding)? {
                return Ok(head);
            }
            let entry = self.state()?.entries.get(&secret).ok_or(Error::NotFound)?;
            if entry.policy != context.policy {
                return Err(Error::Denied);
            }
            if entry.version != expected_version {
                return Err(Error::Conflict);
            }
            let state = Record {
                request,
                fingerprint: binding,
                change: Change::Delete(secret),
                receipt: Receipt {
                    context,
                    secret: None,
                    entry_version: 0,
                    operation: e.0,
                    output: Zeroizing::new(vec![]),
                },
            };
            self.commit(state)
        })
    }
}
