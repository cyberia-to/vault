use super::*;
use crate::{
    record::Payload,
    state::{Change, Receipt},
};

impl<S: CipherStore> Vault<S> {
    /// Reserve a native signature. Release requires copies and fresh authorization.
    pub fn sign<W: Ward>(
        &mut self,
        context: Context,
        request: RequestId,
        signing: crate::SignRequest,
        ward: &W,
    ) -> Result<PendingUse> {
        self.prepare_use(context, request, Operation::Sign(signing), ward)
    }
    pub fn derive_neuron<W: Ward>(
        &mut self,
        context: Context,
        request: RequestId,
        key: NeuronKeyRef,
        ward: &W,
    ) -> Result<PendingUse> {
        self.prepare_use(context, request, Operation::DeriveNeuron(key), ward)
    }
    pub fn prepare_use<W: Ward>(
        &mut self,
        context: Context,
        request: RequestId,
        operation: Operation,
        ward: &W,
    ) -> Result<PendingUse> {
        self.ready(true)?;
        let secret = operation.secret();
        let info = self.read_entry(secret)?.info;
        if info.policy != context.policy {
            return Err(Error::Denied);
        }
        let encoded = operation.encode()?;
        let mut binding_bytes = Encoder::new();
        binding_bytes.byte(3);
        binding_bytes.bytes(&encoded)?;
        let binding = self.binding(context, request, &binding_bytes.0)?;
        let intent = Intent {
            vault: self.id(),
            request,
            context,
            binding,
            kind: IntentKind::Prepare {
                entry: info.clone(),
                operation: operation.clone(),
            },
        };
        ward.with_authorization(&intent, |now| {
            self.current()?;
            if let Some((head, state)) = self.prior(request, binding)? {
                if state.receipt.entry_version != info.version
                    || state.receipt.secret != Some(secret)
                {
                    return Err(Error::Conflict);
                }
                return Ok(PendingUse {
                    vault: self.id(),
                    request,
                    revision: head,
                    context,
                });
            }
            let mut entry = self.read_entry(secret)?;
            let output = crate::use_secret::perform(&mut entry, &operation, now)?;
            let state = Record {
                request,
                fingerprint: binding,
                change: Change::Use(Box::new(entry)),
                receipt: Receipt {
                    context,
                    secret: Some(secret),
                    entry_version: info.version,
                    operation: encoded,
                    output: output.encode(now)?,
                },
            };
            let revision = self.commit(state)?;
            Ok(PendingUse {
                vault: self.id(),
                request,
                revision,
                context,
            })
        })
    }
    /// Delivers inside Ward's current-authorization guard. The host must route
    /// the output only to the destination named in the recorded operation.
    pub fn release<W: Ward, T>(
        &self,
        context: Context,
        pending: &PendingUse,
        copies: &CopyEvidence,
        ward: &W,
        deliver: impl FnOnce(Output) -> Result<T>,
    ) -> Result<T> {
        self.ready(true)?;
        self.current()?;
        if pending.vault != self.id()
            || pending.context != context
            || !copies.covers(&self.store, self.id(), pending.revision)?
        {
            return Err(Error::ReplicationRequired);
        }
        if pending.revision.index > self.head.index {
            return Err(Error::StaleAnchor);
        }
        if self.store.resolve(self.id(), pending.request)? != Some(pending.revision) {
            return Err(Error::Conflict);
        }
        let state = self.read_record(pending.revision)?;
        if state.receipt.context != context || state.request != pending.request {
            return Err(Error::Denied);
        }
        let operation = Operation::decode(&state.receipt.operation)?;
        let info = self.read_entry(operation.secret())?.info;
        if info.policy != context.policy || info.version != state.receipt.entry_version {
            return Err(Error::Denied);
        }
        let intent = Intent {
            vault: self.id(),
            request: pending.request,
            context,
            binding: state.fingerprint,
            kind: IntentKind::Release {
                entry: info,
                operation: operation.clone(),
            },
        };
        ward.with_authorization(&intent, |now| {
            self.current()?;
            let (created_at, output) = Output::decode(&state.receipt.output)?;
            if let Operation::Otp { secret } = operation {
                let entry = self.read_entry(secret)?;
                if let Payload::Otp { period, .. } = &entry.input.0
                    && *period != 0
                    && (now < created_at
                        || now / u64::from(*period) != created_at / u64::from(*period))
                {
                    return Err(Error::Denied);
                }
            }
            deliver(output)
        })
    }
}
