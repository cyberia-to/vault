# Integrating the local custody library

The crate is `cyber-vault`; its Rust library name is `vault`. Its
[local profile](../specs/local-profile.md) is a bounded in-process implementation
for a trusted native host. The host supplies authority, protected entry/output
surfaces and independent recovery material. An application/model must not run
inside that trust boundary merely because it imports the library.

## Build and exercise

Use the sibling `mudra`, `hemera`, `cybergraph`, `bbg` and their stack dependencies.
Cargo path dependencies intentionally reuse those implementations. This initial
slice was checked against local sibling work, including unpublished changes;
the [source manifest](../audit/local-custody-2026-09-16/source-state.json) records
the tested state. `Cargo.lock` does not pin path dependencies to Git revisions.
A clean public clone is not yet a reproducible standalone distribution.

```sh
cargo test --release --all-targets --locked
cargo test --release --no-default-features --locked
cargo run --release --example recovery --locked
cargo clippy --all-targets --no-deps --locked -- -D warnings
cargo fmt --package cyber-vault --check
```

`graph-store` is enabled by default. Disabling it builds the custody library and
`CipherStore` port without Cybergraph's storage feature. The
[recovery example](../examples/recovery.rs) uses only synthetic credentials and
temporary directories; its `DemoWard` is not an authentication implementation.

## Connect storage and authority

`GraphStore::from_database(database)` shares the existing BBG `Database` owner
with Cybergraph. Use this in a node; do not reopen the same physical database
through a second owner. `GraphStore::open(path)` is a convenience for a standalone
default Fjall store. Backend choice remains BBG's responsibility.

`CipherStore` carries only ciphertext. Its `append` implementation must enforce
durable atomic compare-and-swap, exact request deduplication and uncertainty
reporting. Supplying another implementation inherits those obligations.
It now supplies `history_page(vault, after, limit)`, with strictly ascending rows
after the cursor. Recovery and copying continue until the exact selected anchor
and end-of-history check; a short page is not the end. `history()` remains an
explicit convenience collector and is not used by recovery or replication.

The [Cybergraph boundary check](../audit/cybergraph-sync-boundary-2026-09-16/README.md)
demonstrates raw graph read/copy/reopen compatibility. `Vault::replicate` remains
a local helper; importing this crate does not activate Foculus networking or a
live private-history synchronization service. Graph archive `Transfer` seals
its source writer and must not be used as a live replica loop.

Implement `Ward::with_authorization`. Authenticate the actor and policy, inspect
the exact typed `Intent`, and hold current authorization until the callback
finishes. Supply trusted Unix time in seconds to the callback. A caller-provided
`Context` or `PendingUse` is not permission. The library provides no permissive
production Ward. Test adapters exist only in tests and the synthetic example.

## Create, retain and use

1. Generate a random `VaultId`, request IDs and an independent high-entropy
   32-byte recovery factor inside the trusted host. Collect an unlock passphrase
   through protected input. Never put them in command arguments, environment
   variables, diagnostics or an agent conversation.
2. Call `Vault::create`. Retain the vault locator, exact returned `Revision`,
   recovery factor and replica locators independently of the working store. An
   ordinary neuron spell does not reconstruct externally chosen credentials.
3. Construct typed `SecretInput` values in zeroizing owned buffers and call
   `put`. Store only the resulting `SecretRef` in ordinary clients. Replacement
   requires the expected entry version and cannot change its secret kind.
4. Call `prepare_use` (or `derive_neuron`). Vault persists the result/reservation
   before returning `PendingUse`. The pending handle contains no output secret.
5. Call `replicate` with two or more distinct configured replica stores. It
   verifies complete matching ciphertext history by readback and returns
   `CopyEvidence` tied to a revision. Copies of an older revision cannot protect
   a newer reservation. Failure-domain labels must describe real deployment
   independence; two directories on one disk do not provide it.
6. Call `release` with the pending handle and copy evidence. Vault rechecks entry
   generation, scope and fresh Ward authority. Route the callback's `Output` only
   to the recorded approved destination/surface. Secret outputs use zeroizing
   buffers; any copies made by the host become its custody responsibility.

Metadata inspection also requires Ward authorization. Use `inspect_page` for
bounded responses, continuing after the last returned SecretRef until the page
is empty. `inspect` explicitly collects the complete visible catalog. `lock`
drops the library's keys and in-memory catalog index; encrypted copy operations
do not require unlocking. Entry payloads are decrypted on demand.
Neither root spells nor derived private keys have an export/getter operation.

## Reopen, retry and recover

`open(store, id, anchor, password)` verifies the whole history to an independently
retained exact anchor. It resumes the existing writer. The host must ensure there
is only one active writer; opening a different replica with the password does
not fence the original. A store-supplied latest head is not a trusted freshness
anchor. Older/newer heads, missing history and corrupt packets reject.

Repeat a request with its original ID and exact inputs to recover its original
receipt, even after subsequent writes. Changes under that ID reject. HOTP and
recovery-code reservations survive restart; a new request cannot reuse their
reserved state. Delivery of a TOTP receipt outside its original time window
rejects. Replaced/deleted credentials cannot release earlier pending results.

On `CommitUnknown`, the session freezes. Retain `pending_commit()` alongside
the prior anchor and request ID; close the old session/store, reconcile the
durable request receipt, then reopen against the matching retained anchor. An
unknown initial `create` has no returned candidate anchor: stop that creation
flow for explicit host reconciliation; do not silently start another vault.

`recover(store, id, anchor, recovery_factor)` verifies and decrypts the selected
revision but remains `RecoveryReadOnly`. It permits authorized metadata
inspection and encrypted copying. It cannot release secrets, reserve operations
or become an active writer. Writer promotion and the portable recovery ceremony
are the next deployment layer, not hidden defaults in this API.

## Capacity and qualification

There is no configured total-entry, tombstone or lifetime-revision limit. Each
new revision stores one encrypted change and its receipt; it never rewrites the
complete catalog. Read/decoder budgets still bound individual packets (4 MiB),
secret values (16 KiB) and page responses. The history position uses the existing
u64 format with checked overflow. Practical capacity depends on storage and RAM.

The in-memory current-entry/tombstone index grows with IDs, not secret payload
bytes. Opening still replays history, and copying verifies retained history in
pages. There is no checkpoint/compaction acceleration yet. Existing v1 snapshots
remain readable and may append v2 changes without rewriting original ciphertext
or receipts; old clients must upgrade before reading/writing the v2 tail.

There is no factor rotation, authenticated network receipt, retention lease or
distributed fencing yet. Root custody inside this library is an API boundary,
not protection against a compromised host process. See the
[capacity/recovery evidence](../audit/unbounded-history-2026-09-16/README.md) and
[initial qualification limits](../audit/local-custody-2026-09-16/README.md).
