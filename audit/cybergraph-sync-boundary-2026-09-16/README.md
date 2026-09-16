# Cybergraph and synchronization boundary — 2026-09-16

**Storage: integrated. Live private synchronization: incomplete.** Vault stores
ordinary encrypted Cybergraph Blob content and application receipts through the
shared BBG owner. Its current replication helper traverses/copies history inside
Vault. A shared authenticated live-history sync adapter is still required.

## Checked execution path

```text
Vault::put / prepare_use
  → GraphStore::append
  → ApplicationGraph::commit(Proposal)
  → ApplicationStore::apply
  → Database::transaction
  → Fjall atomic batch with PersistMode::SyncAll
```

Content, selected head, contiguous history and exact request receipt share the
BBG transaction. `GraphStore::from_database` reuses its owner and failure state.
There is no separate Vault database, WAL or plaintext seed file. The default
crate enables Fjall; an explicitly enabled HDD backend remains the owner's
selection. This review executed Fjall tests, not an HDD qualification.

This is Cybergraph's **private application namespace** path. It does not create
native SignalChain entries or put application rows into the public BBG polynomial
commitment. Shared storage does not imply shared proof/publication semantics.

## Direct tests

Two [new integration tests](../../tests/cybergraph_boundary.rs) exercise the
boundary without treating Vault's own copy loop as proof of graph compatibility:

1. Create a synthetic Vault through a shared Database; inspect its content,
   history and original receipts through an ordinary `ApplicationGraph`; lock
   Vault; copy the packets using only graph `Proposal` commits into another
   store; check exact retries; close both stores and remove the source; reopen
   the destination and recover its catalog read-only with the independent factor.
2. Verify a graph proposal missing its head content cannot advance the head.
   Then deliberately bind a valid opaque packet to the wrong request in a raw
   graph proposal. Graph content validity accepts the Blob, while Vault recovery
   rejects its missing original receipt. Application admission remains necessary.

The run included these **2 tests plus 10 existing storage/recovery/fault tests**:
all **12 passed**. The latter cover shared owner isolation, stale/omitted/corrupt
history, uncertain commits, competing writers, divergent copies, reserved HOTP,
interrupted copy resumption and acknowledgements without retained packets.
[Command and exit status](checks.json) · [output](tests.log).

Only synthetic temporary stores were used. No network, real user vault or real
secret was opened. The receipt IDs in the direct-copy test are retained by its
source fixture; this demonstrates graph interoperability, not an already shipped
generic history exporter or remote authorization protocol.

## Findings

| Finding | Consequence / required boundary |
|---|---|
| `vault/src/replication.rs` owns a synchronous local read/append/readback loop | Useful development coverage; production traversal/transfer must move behind Cybergraph's shared live-sync port |
| `CopyEvidence` is in-memory evidence with caller-configured IDs/failure domains | No authenticated peer receipts, durable protection ledger, retention expiry or ongoing availability checks; do not call this network `Protected(R)` |
| Every copy/restore validates complete retained history; each revision contains a full catalog snapshot | Incremental packet copying still performs O(history) validation reads; retained bytes grow with catalog × revisions. A bounded checkpoint/delta design is still needed |
| Cybergraph `application::Transfer` delegates to BBG's sealed archive transfer | It seals/fences the old source, reserves target namespaces and imports an archive. Reusing it for every live sync would disable the writer and has the wrong collision semantics |
| Foculus contains `SyncNode`, `VDiskManager`, chunk distribution and a timestamp-based file registry | These are existing stack capabilities, but the registry's LWW rule must never choose Vault heads or merge counters/grants. Its file writes/registry state are not BBG application commit receipts |
| Generic Blob validity cannot authenticate a Vault writer or validate its envelope/request relationship | A private namespace/role/epoch admission adapter is required before remote publication; AEAD/decrypted state validation remains inside custody |
| Exact restore anchors and read-only recovery exist, but distributed writer fencing does not | A restored replica cannot be promoted safely through the present library API |

`foculus/src/node.rs` additionally serves a whole file registry, uses separate
filesystem writes and marks delta/heartbeat wire operations as not yet connected.
That handler provides no Vault-scoped enrollment/admission or authenticated
durable application receipt. Its chunk path is not a drop-in private namespace
endpoint. This is a boundary review of that code, not a full Foculus audit.

## Ownership to preserve

- **Vault:** secret format, encryption, allowed uses, conservative counter state,
  required replica policy and verification of decrypted recovery results.
- **Cybergraph:** private application history/closure and its common live-sync
  entry point, including application-specific admission hooks.
- **Foculus + selected transport:** shared synchronization/session mechanics,
  bounded transfer and the explicitly selected writer-ordering/fencing profile.
  Tape/Radio own the selected framing/transport, not custody policy.
- **BBG Database:** atomic receiver publication, durable receipts/cursors and
  backend barriers under the shared owner.

The deployment sequence is: authenticate peer and namespace → pin anchor/epoch →
transfer missing immutable ciphertext under budgets → validate closure/lineage →
durably publish through BBG → authenticate and retain the exact revision receipt
→ update policy status. Delivery ACK, a root without its content and a local
failure-domain label must never substitute for those steps.

The [sync contract](../../specs/synchronization.md#shared-graph-boundary) now fixes
this boundary. The runtime remains the bounded local profile; this review changes
tests/contracts and does not claim a completed network implementation.

## Source provenance

Reviewed local files: Vault `src/{graph,replication,store,custody}.rs`;
Cybergraph `src/application.rs`, `src/application/{transfer,archive}.rs` and
`specs/applications.md`; BBG `rs/src/storage/application.rs`,
`rs/src/storage/database/{mod,backend_fjall,backend_redb}.rs` and
`specs/{application-transfer,application-coordination}.md`; Foculus
`src/{lib,node,store,vdisk}.rs`; soft3's
`proposals/cybergraph-sync-tape-architecture.md` (its opening note records the
`sync` → Foculus merger). Some older BBG/Foculus prose still names pre-merger
owners, so ownership claims were checked against current modules and manifests.

[Source fingerprints](source-state.json) record the inspected heads and local
file digests. Sibling repositories contain concurrent uncommitted work; this
change neither edits nor publishes it. Registry dependencies are locked, while
local path dependencies still require compatible sibling checkouts.
