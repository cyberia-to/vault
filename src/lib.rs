//! Typed custody inside a trusted host. See specs/local-profile.md for its limits.
#![forbid(unsafe_code)]

mod codec;
mod crypto;
mod custody;
#[cfg(feature = "graph-store")]
mod graph;
mod history;
mod model;
mod operation;
mod record;
mod replication;
mod state;
mod store;
mod use_secret;

pub use custody::{AccessMode, Vault};
#[cfg(feature = "graph-store")]
pub use graph::GraphStore;
pub use model::*;
pub use operation::{
    Derivation, Intent, IntentKind, NeuronKeyRef, Operation, Output, PendingUse, Ward,
};
pub use record::{Entry, EntryInfo, OtpAlgorithm, SecretInput, SecretKind};
pub use replication::{CopyEvidence, Replica};
pub use store::{CipherStore, StoredRevision};
