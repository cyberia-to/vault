mod mutations;
mod uses;

use crate::{
    codec::Encoder,
    crypto::{Header, Keys, Packet},
    state::State,
    store::{checked, identity},
    *,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    Active,
    RecoveryReadOnly,
    Locked,
    Frozen,
}

/// Custody library for a trusted host, with no root/key getters.
pub struct Vault<S: CipherStore> {
    store: S,
    header: Header,
    keys: Option<Keys>,
    state: Option<State>,
    head: Revision,
    mode: AccessMode,
    pending_commit: Option<Revision>,
}
impl<S: CipherStore> Vault<S> {
    pub fn create<W: Ward>(
        store: S,
        id: VaultId,
        request: RequestId,
        context: Context,
        password: &[u8],
        recovery: &[u8; 32],
        ward: &W,
    ) -> Result<Self> {
        let intent = Intent {
            vault: id,
            request,
            context,
            kind: IntentKind::Create,
            binding: [0; 32],
        };
        ward.with_authorization(&intent, |_| {
            if store.head(id)?.is_some() {
                return Err(Error::AlreadyExists);
            }
            let (header, keys) = Header::create(id, password, recovery)?;
            let state = State::empty(request, context);
            let packet = Packet::seal(header.clone(), &keys, request, None, state.encode()?)?;
            let bytes = packet.encode()?;
            let expected = Revision {
                index: 0,
                commit: identity(&bytes),
            };
            let head = store.append(id, request, None, bytes)?;
            if head != expected {
                return Err(Error::CommitUnknown);
            }
            Ok(Self {
                store,
                header,
                keys: Some(keys),
                state: Some(state),
                head,
                mode: AccessMode::Active,
                pending_commit: None,
            })
        })
    }
    /// `anchor` must come from independent trusted host state, not from this store.
    pub fn open(store: S, id: VaultId, anchor: Revision, password: &[u8]) -> Result<Self> {
        let packet = load_packet(&store, anchor)?;
        if packet.header.vault != id {
            return Err(Error::Authentication);
        }
        let keys = packet.header.unlock(password)?;
        Self::load(store, id, anchor, packet.header, keys, AccessMode::Active)
    }
    /// Recovery cannot activate a replacement writer in this profile.
    pub fn recover(store: S, id: VaultId, anchor: Revision, factor: &[u8; 32]) -> Result<Self> {
        let packet = load_packet(&store, anchor)?;
        if packet.header.vault != id {
            return Err(Error::Authentication);
        }
        let keys = packet.header.recover(factor)?;
        Self::load(
            store,
            id,
            anchor,
            packet.header,
            keys,
            AccessMode::RecoveryReadOnly,
        )
    }
    fn load(
        store: S,
        id: VaultId,
        anchor: Revision,
        header: Header,
        keys: Keys,
        mode: AccessMode,
    ) -> Result<Self> {
        let history = crate::replication::chain(&store, id, anchor)?;
        let mut state = None;
        for head in history {
            let packet = load_packet(&store, head)?;
            if packet.header != header {
                return Err(Error::Corrupt);
            }
            let decoded = State::decode(&packet.open(&keys)?)?;
            if decoded.request != packet.request
                || decoded
                    .entries
                    .values()
                    .any(|e| e.info.version == 0 || e.info.version > head.index)
            {
                return Err(Error::Corrupt);
            }
            if store.resolve(id, decoded.request)? != Some(head) {
                return Err(Error::Corrupt);
            }
            state = Some(decoded);
        }
        Ok(Self {
            store,
            header,
            keys: Some(keys),
            state,
            head: anchor,
            mode,
            pending_commit: None,
        })
    }
    pub fn id(&self) -> VaultId {
        self.header.vault
    }
    pub fn revision(&self) -> Revision {
        self.head
    }
    pub fn mode(&self) -> AccessMode {
        self.mode
    }
    /// Exact locally prepared anchor to retain while resolving CommitUnknown.
    pub fn pending_commit(&self) -> Option<Revision> {
        self.pending_commit
    }
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn into_store(self) -> S {
        self.store
    }
    pub fn lock(&mut self) {
        self.keys.take();
        self.state.take();
        self.mode = AccessMode::Locked;
    }

    pub fn inspect<W: Ward>(&self, context: Context, ward: &W) -> Result<Vec<EntryInfo>> {
        self.ready(false)?;
        let intent = Intent {
            vault: self.id(),
            request: RequestId([0; 32]),
            context,
            kind: IntentKind::Inspect,
            binding: [0; 32],
        };
        ward.with_authorization(&intent, |_| {
            self.current()?;
            Ok(self
                .state()?
                .entries
                .values()
                .filter(|e| e.info.policy == context.policy)
                .map(|e| e.info.clone())
                .collect())
        })
    }
    pub fn replicate<T: CipherStore>(&self, replicas: &[Replica<T>]) -> Result<CopyEvidence> {
        crate::replication::replicate(&self.store, self.id(), self.head, replicas)
    }
    fn ready(&self, writing: bool) -> Result<()> {
        match self.mode {
            AccessMode::Locked => Err(Error::Locked),
            AccessMode::Frozen => Err(Error::Frozen),
            AccessMode::RecoveryReadOnly if writing => Err(Error::ReadOnly),
            _ => Ok(()),
        }
    }
    fn current(&self) -> Result<()> {
        if self.store.head(self.id())? != Some(self.head) {
            Err(Error::StaleAnchor)
        } else {
            Ok(())
        }
    }
    fn state(&self) -> Result<&State> {
        self.state.as_ref().ok_or(Error::Locked)
    }
    fn keys(&self) -> Result<&Keys> {
        self.keys.as_ref().ok_or(Error::Locked)
    }
    fn binding(&self, context: Context, request: RequestId, operation: &[u8]) -> Result<[u8; 32]> {
        let mut e = Encoder::new();
        e.fixed(&self.id().0);
        e.fixed(&request.0);
        e.fixed(&context.actor.0);
        e.fixed(&context.policy.0);
        e.bytes(operation)?;
        self.keys()?.fingerprint(&e.0)
    }
    fn prior(&self, request: RequestId, binding: [u8; 32]) -> Result<Option<(Revision, State)>> {
        let Some(head) = self.store.resolve(self.id(), request)? else {
            return Ok(None);
        };
        if head.index > self.head.index {
            return Err(Error::StaleAnchor);
        }
        let state = self.read_state(head)?;
        if state.request != request || !bool::from(state.fingerprint.ct_eq(&binding)) {
            return Err(Error::Conflict);
        }
        Ok(Some((head, state)))
    }
    fn read_state(&self, head: Revision) -> Result<State> {
        let packet = load_packet(&self.store, head)?;
        if packet.header != self.header {
            return Err(Error::Corrupt);
        }
        let state = State::decode(&packet.open(self.keys()?)?)?;
        if state.request != packet.request {
            return Err(Error::Corrupt);
        }
        Ok(state)
    }
    fn commit(&mut self, state: State) -> Result<Revision> {
        let packet = Packet::seal(
            self.header.clone(),
            self.keys()?,
            state.request,
            Some(self.head),
            state.encode()?,
        )?;
        let bytes = packet.encode()?;
        let expected = Revision {
            index: packet.index,
            commit: identity(&bytes),
        };
        match self
            .store
            .append(self.id(), state.request, Some(self.head), bytes)
        {
            Ok(head) if head == expected => {
                self.head = head;
                self.state = Some(state);
                Ok(head)
            }
            Ok(_) => {
                self.pending_commit = Some(expected);
                self.mode = AccessMode::Frozen;
                Err(Error::CommitUnknown)
            }
            Err(e) => {
                // Keep no usable session after an uncertain or conflicting write.
                if matches!(e, Error::CommitUnknown | Error::Conflict | Error::Frozen) {
                    self.mode = AccessMode::Frozen;
                }
                if e == Error::CommitUnknown {
                    self.pending_commit = Some(expected);
                }
                Err(e)
            }
        }
    }
}
pub(crate) fn load_packet<S: CipherStore>(store: &S, r: Revision) -> Result<Packet> {
    let value = checked(store.read(r)?, r)?;
    let packet = Packet::decode(&value.bytes)?;
    if packet.index != r.index {
        return Err(Error::Corrupt);
    }
    Ok(packet)
}
