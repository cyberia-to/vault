# Implementation order

The first local library now covers typed records, durable encrypted history,
protected-use reservations, two-store readback verification and read-only
recovery. [Evidence](../audit/local-custody-2026-09-16/README.md) records exactly
what ran. It covers parts of A–D; none of the deployment packages below is fully
qualified. Each package produces reviewable code and evidence in `audit/`.

| Package | Work | Exit evidence |
|---|---|---|
| A — pin the first profile | Canonical schemas/encodings and bounds; crypto/envelope/KDF profiles; OS isolation and protected input; Ward freshness; replica receipt and fencing/recovery-anchor choice | Versioned profile covers every open boundary in specs/README; threat and failure assumptions explicit |
| B — local custody and durable records | Typed service/client boundary, Mudra adapters, Cybergraph/BBG transactions and reopen; synthetic fixture imports; protected operations and reservations | C01–C05, D01–D03 and identity compatibility; no raw key path to applications |
| C — encrypted replication | Existing stack transfer adapter, complete-closure receipts, protection status, portable locators and retention | S01–S04 with interrupted transfer, provider loss and false acknowledgements |
| D — recovery and authority transfer | Independent capsule opening, checkpoint/tail verification, freshness, writer handover/fencing and offline reservation recovery | S05–S06 and R01–R06; complete device-loss demonstration |
| E — product integration and qualification | Replace cyb/Neuron legacy custody clients, expose protection states, explicit migration, backend/platform fault qualification | M01–M02, D04, measured end-to-end gates and a scoped release |

Implement packages B–D first against isolated synthetic stores. Do not migrate
real user custody until reopen, independent restore and compatibility gates
pass. Preserve original recovery material and legacy ciphertexts during explicit
migration; do not claim deletion from SSDs or backups.

## Next implementation sequence

1. Publish compatible Cybergraph/BBG/Mudra dependency revisions and build this
   slice from clean checkouts in CI. The initial evidence uses local sibling work.
2. Wrap the library in native custody isolation and implement real Ward caller
   authentication, current authorization and protected input/output adapters.
   Keep the same `derive_neuron` results while moving Neuron clients behind them.
3. Build the shared **live private application-history sync adapter behind
   Cybergraph**, using Foculus and the selected stack transport. Move Vault's
   local copy loop behind that port; add authenticated replica identities,
   scope/epoch admission, durable receipts, retention and resumable bounded
   transfer. Keep sealed archive migration separate and reject LWW head selection.
   Replace local copy labels with a concrete deployment policy and evidence.
4. Implement portable recovery locators, independent anchor retention, uncertain
   genesis reconciliation and writer fencing/handover. Recovery must activate a
   replacement device only after the previous writer is fenced.
5. Exercise physical/process interruption and device-loss drills across the
   selected backends/platforms, then qualify migration and a scoped release.

Password/recovery-factor rotation, efficient checkpoints/compaction and remaining
secret-use adapters also need versioned formats and tests before general use.

Later profiles may add concurrent devices, hardware-native custody, passkeys,
private proving, threshold recovery and stronger traffic privacy. They must
preserve the typed-secret, durability and evidence contracts. They are not
prerequisites for demonstrating the first storage/recovery use case.
