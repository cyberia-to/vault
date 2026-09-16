---
title: vault specifications
status: draft
version: 0.1
---
# Specification map

Vault owns the secure use, durable retention and private synchronization of
typed secrets. Safe storage and recovery are its first product requirement.
An encrypted file with no recoverable copy does not satisfy the product.

These documents define the initial design contract. MUST, SHOULD and MAY state
requirements on future conforming implementations, not present capabilities.
Logical fields and operation sketches do not freeze a wire ABI or select
unqualified cryptographic parameters.

| Contract | Defines |
|---|---|
| [Architecture](architecture.md) | Owners, dependencies, trust boundaries and initial deployment profile |
| [Secrets](secrets.md) | Record types, allowed uses, disclosure and `derive_neuron` |
| [Authorization](authorization.md) | Ward decisions, protected operations, retries and revocation |
| [Storage](storage.md) | Sealed records, complete revisions and durable acknowledgement |
| [Synchronization](synchronization.md) | Replicas, device roles, writer epochs, conflicts and retention |
| [Recovery](recovery.md) | Independent recovery material, freshness and loss scenarios |
| [Conformance](conformance.md) | Cross-stack acceptance gates and release evidence |
| [Local custody profile](local-profile.md) | Bounded library format, cryptographic parameters and trusted-host assumptions |

## Fixed decisions

1. Vault has its own repository and reusable component boundary. Shipping it
   does not require another user-facing binary or a second protocol subject.
2. Seeds, private keys and imported credentials share a typed custody service;
   their use and disclosure policies differ.
3. Records, metadata and protected-use state have durable encrypted storage.
   Derivation cannot reconstruct externally chosen secrets or lost history.
4. Replication carries encrypted data; storing a copy grants no decryption or
   signing authority. The user's data is portable across conforming stores.
5. The first synchronization profile has one active writer. Promotion requires
   an explicit handover or fenced recovery; there is no automatic failover.
6. A result names its revision and durability/recovery evidence. Local success
   does not imply replication, freshness, availability or consensus finality.
7. Existing cryptographic identity profiles retain their bytes. Programmable
   private authority remains compatible with this boundary.

## Initial profile and remaining parameters

The target profile is `single-writer-replicated-v1`: one isolated native custody
service, a local durable working store, and at least two encrypted replicas in
separately configured failure domains excluding the writer. It tolerates loss
of the writer and one replica only while the other retains the complete selected
revision and the independent recovery material survives.

Before coding each boundary, pin its canonical encoding, cryptographic suite
and limits, OS isolation/entry surface, Ward freshness method, replica receipt
authentication and recovery-anchor mechanism. These details belong to explicit
profile definitions here; they MUST NOT emerge as undocumented implementation
defaults. [The roadmap](../roadmap/README.md) makes those decisions the first
implementation package.

`local-custody-v2` pins a smaller library profile for development. It does not
relax the native service, authenticated replication or writer-transfer gates of
the target deployment. Implementation evidence belongs in [audit](../audit/README.md).

The library profile imposes no total record or revision count ceiling. It stores
encrypted per-entry changes, reads history in pages and preserves v1 snapshots
as a readable immutable prefix. Per-packet resource budgets are distinct from
capacity. Exact encodings and compatibility are in the local profile.
