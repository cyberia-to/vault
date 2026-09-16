# Remove Vault capacity caps — 2026-09-16

Vault no longer imposes the initial 128-entry or 4096-revision ceilings. Both
constants and their enforcement paths are removed. New commits store one
encrypted entry change and its receipt; history is read in bounded pages until
the exact selected anchor. The total catalog is not encoded into one packet.

## Why the old limit existed

The first implementation serialized a complete catalog on every mutation/use.
It introduced an arbitrary 128-entry count and read history with a single BBG
request. BBG's 4096-row **page** bound was incorrectly turned into a lifetime
revision bound. Neither number was a product requirement or measured capacity.
Increasing those numbers would leave an aggregate packet-size limit and growing
write amplification. This change removes that storage-model cause as well.

## Implementation

- `VSTATE2` records hold a genesis, put, delete or use/reservation change plus
  the original encrypted receipt. Each affected entry is a separate encrypted
  graph packet; unchanged entries are referenced by their existing locations.
- The in-memory catalog contains locations, versions, kinds, policy references
  and tombstone IDs. Secret payloads are decrypted on demand. A mutation does
  not clone/re-encode all entries or tombstones.
- `CipherStore::history_page` replaces an all-history read as the required port.
  Recovery/copy verification use 256-row pages and check sequence, predecessor,
  request coverage, exact anchor, excess rows and the final store head. Short
  pages do not terminate a walk. `history()` explicitly collects when requested.
- `inspect_page` bounds metadata response allocation. `inspect()` remains the
  explicit full-catalog convenience API.
- Copy evidence retains the verified anchor rather than every historical head.
  Release checks both that anchor and the pending result against the store's
  history positions, preventing evidence from another branch covering a result.
- Existing v1 snapshots remain readable. They can be followed by v2 changes
  without rewriting ciphertext, IDs or request fingerprints. A v1 snapshot
  appearing after v2 is rejected. Old clients need upgrading for the v2 tail.

The outer packet, encryption, key wrapping, derivation and native neuron formats
are unchanged. Cybergraph still owns content/history and BBG still owns atomic
durability; no new database or network engine was added.

## Executed evidence

The full release suite passed **32 tests**; the adapter-free configuration passed
**7 tests**. Clippy (`--all-targets --no-deps -- -D warnings`), package formatting
and the standalone synthetic recovery example passed. Existing vendored Fjall
warnings remain dependency warnings and were not modified by this change.

The [capacity test](../../tests/capacity.rs) uses actual temporary Fjall databases:

| Property | Observed/check performed |
|---|---|
| Catalog | 4,353 entries inserted; 4,352 remain live after one deletion |
| History | 4,356 committed revisions including genesis |
| Live secret payload bytes | 4,456,448 bytes (4.25 MiB), exceeding the old whole-snapshot packet budget before any metadata |
| Change size | Latest one-entry insert packet remains below 8 KiB despite the larger catalog |
| Reopen/retry | Close and reopen the physical owner; retry the first request after thousands of writes; receive its original revision |
| Paging failures | Omit a row or the entire remaining suffix after index 4095; both restores reject |
| Deletion | Deleted ID cannot be recreated; tombstone and absence survive recovery |
| Replication | Copy/verify complete history onto two stores while Vault is locked |
| Release | Reopen and release the original protected result with its evidence and current test Ward |
| Loss/recovery | Remove primary storage and one copy; restore from the other using the independent factor |
| Catalog pagination | Enumerate all surviving IDs in 127-entry pages with no omissions/duplicates |

The scale scenario took **83.64 seconds** in this run, including multiple complete
verification walks, local durable writes/copies, reopen and fault cases. All
stores were on one macOS arm64 host; this is a functional regression test, not
a remote-throughput or physical failure-independence benchmark.

[Compatibility tests](../../src/custody/compatibility_tests.rs) reconstruct the
original v1 write encoding, append a v2 tail, check the old exact request receipt
and unchanged ciphertext, use the original credential, replicate/recover the
mixed history and reject an authenticated downgrade. Codec fixtures cover both
versions. Existing authorization, OTP, integrity and commit-failure tests remain.

[Commands/results](checks.json) · [full suite](tests.log) ·
[minimal-feature tests](core-tests.log) · [Clippy](clippy.log) ·
[format](format.log) · [recovery demo](example.log) ·
[source state](source-state.json).

## Practical bounds and remaining work

There is no configured total-entry, tombstone or revision count limit. History
uses the existing checked u64 position; storage and host memory remain finite.
Per-operation bounds remain: packet decoding, secret/field sizes and page size.
They no longer limit how many individually valid records a Vault can retain.

Reopen still replays the full authenticated history and builds an in-memory
location/tombstone index. Its cost grows with actual history/IDs; checkpoints,
compaction and a persistent index remain performance work. No infinite-capacity
or constant-time recovery claim follows from removing count quotas.

Only synthetic fixtures were used. Real custody migration, process isolation,
production Ward, shared network sync, authenticated remote retention receipts
and distributed writer fencing remain outside this local library qualification.
Path dependencies use compatible sibling working trees; this change does not
publish or modify those repositories.
