//! Explicit local-operator custody; not a production Ward or untrusted IPC service.
//! Shared by the Vault CLI and trusted embedded hosts such as Neuron's local CLI.
#[doc(hidden)]
pub mod host;
#[doc(hidden)]
pub mod io;
#[doc(hidden)]
pub mod owner;

use crate::{
    Context, GraphStore, NeuronKeyRef, Operation, Output, Replica, RequestId, SignRequest, Vault,
    VaultId,
};
use host::{Host, JournaledStore};
use owner::{Grant, Owner};
use std::{path::Path, sync::Arc};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A selected local key, unlocked by its OS owner. Only public credentials and
/// signatures cross this API. The caller owns action interpretation/permission.
pub struct Signer {
    vault: Vault<Arc<JournaledStore>>,
    host: Host,
    replicas: Vec<Replica<GraphStore>>,
    key: NeuronKeyRef,
    subject: [u8; 32],
}
impl Signer {
    /// Unlock through Vault's protected input surface, never argv or environment.
    pub fn prompt_open(directory: &Path, key: NeuronKeyRef, secrets_stdin: bool) -> Result<Self> {
        let password = io::secret("Unlock Vault password: ", secrets_stdin)?;
        Self::open(directory, key, password.as_bytes())
    }

    /// The trusted host owns this input ceremony. The password is not retained.
    pub fn open(directory: &Path, key: NeuronKeyRef, password: &[u8]) -> Result<Self> {
        let host = Host::open(directory, false)?;
        let state = host.state()?;
        let mut vault = Vault::open(
            host.store.clone(),
            VaultId(state.vault),
            host.opening_anchor()?,
            password,
        )?;
        host.settle(vault.revision())?;
        let replicas = host::replicas(&host)?;
        let context = state.context();
        let inspect = Owner {
            vault: vault.id(),
            context,
            request: RequestId([0; 32]),
            grant: Grant::Inspect,
        };
        let version = vault.entry_info(context, key.root, &inspect)?.version;
        let name = fingerprint(&key)?;
        // Entry versions are revision indexes and are never reused, so a
        // retained subject is exact. Opening an already derived key therefore
        // commits no receipt and reads back no history.
        let subject = match host.subject(name, version)? {
            Some(subject) => subject,
            None => {
                let subject = Self::derive(&host, &mut vault, context, &key, &replicas)?;
                host.remember_subject(name, version, subject)?;
                subject
            }
        };
        Ok(Self {
            vault,
            host,
            replicas,
            key,
            subject,
        })
    }

    /// One protected use per key reference and root version: it commits an
    /// encrypted receipt, verifies the copies and releases public credentials.
    fn derive(
        host: &Host,
        vault: &mut Vault<Arc<JournaledStore>>,
        context: Context,
        key: &NeuronKeyRef,
        replicas: &[Replica<GraphStore>],
    ) -> Result<[u8; 32]> {
        let request = RequestId::random()?;
        let ward = Owner {
            vault: vault.id(),
            context,
            request,
            grant: Grant::Use(Operation::DeriveNeuron(key.clone())),
        };
        let pending = vault.derive_neuron(context, request, key.clone(), &ward)?;
        host.settle(vault.revision())?;
        let copies = vault.replicate(replicas)?;
        let subject = vault.release(context, &pending, &copies, &ward, |out| match out {
            Output::Neuron { subject, .. } => Ok(subject),
            _ => Err(crate::Error::Corrupt),
        })?;
        Ok(subject)
    }

    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }

    /// Must run inside the embedding host's current action-authorization guard.
    /// The request ID must be independently random; retain it for exact retries.
    pub fn sign(&mut self, request: RequestId, statement: [u8; 32]) -> Result<Vec<u8>> {
        let signing = SignRequest {
            key: self.key.clone(),
            subject: self.subject,
            statement,
        };
        let ward = Owner {
            vault: self.vault.id(),
            context: self.host.state()?.context(),
            request,
            grant: Grant::Use(Operation::Sign(signing.clone())),
        };
        let pending = self
            .vault
            .sign(ward.context, request, signing.clone(), &ward)?;
        self.host.settle(self.vault.revision())?;
        let copies = self.vault.replicate(&self.replicas)?;
        Ok(self
            .vault
            .release(ward.context, &pending, &copies, &ward, |out| match out {
                Output::Signature { request, evidence } if request == signing => Ok(evidence),
                _ => Err(crate::Error::Corrupt),
            })?)
    }
}

/// A stable name for a key reference, over its canonical operation encoding.
fn fingerprint(key: &NeuronKeyRef) -> Result<[u8; 32]> {
    let mut bytes = b"vault:local:subject:v1:".to_vec();
    bytes.extend_from_slice(&Operation::DeriveNeuron(key.clone()).encode()?);
    Ok(*hemera::hash(&bytes).as_bytes())
}
