---
title: vault conformance and release gates
status: draft
version: 0.1
---
# Conformance

This is the first soft3 storage/synchronization acceptance scenario. Passing
component tests does not establish its end-to-end guarantees. Each advertised
platform, backend, crypto/custody and sync profile needs identified revisions,
limits and reproducible evidence in `audit/`.

The first qualification setup has an isolated native writer, a durable local
store and two replica stores in declared independent failure domains. Use
synthetic secrets for every supported type. Required types for the first product
slice are spell/key, password/PIN, TOTP, HOTP, recovery codes and service tokens;
passkeys and hardware custody require separately qualified profiles.

## Acceptance matrix

| ID | Scenario | Required result |
|---|---|---|
| C01 | Create/import each supported type, reboot before read/use | Exact retained record and allowed operations; no empty replacement |
| C02 | Change secret kind, copy a handle, forge a grant or redirect credential delivery | Denied without secret release or state mutation |
| C03 | Root/key API, debug/errors, UI/history/clipboard, agent context and malicious proof output | No unintended secret exposure; explicit approved entry disclosure remains functional |
| C04 | Exact and conflicting operation retries, including after revocation | Exact use reconciles without duplicate consumption; conflict/current disclosure denial remains enforced |
| C05 | Revoke versus use, expiry, stale policy and rolled-back lease clock | Defined linearization/freshness behavior; no weaker fallback |
| D01 | Crash before/during/after content/head/receipt commit | Old or complete new revision; Unknown reconciled before dependent effects |
| D02 | Chunk absent, corrupt, substituted, oversized or unsupported on reopen | Bounded failure; no head/cursor advancement or partial success |
| D03 | Disk full, competing writer, read/commit error and configured backend restart | No success without the selected barrier; existing data and request identity preserved |
| D04 | Physical power cut on each advertised storage profile | Acknowledged local data survives under documented hardware/filesystem assumptions |
| S01 | Fresh replicas, interrupted/duplicate/reordered transfer and restart | Complete verified closure, durable acknowledgement and idempotent resumption |
| S02 | Transport-only acknowledgement; manifest-only receiver; dishonest storage claim exposed by readback | Transport ACK never counts; conforming receiver refuses a closure receipt; failed readback rejects/degrades the claimed copy |
| S03 | Loss of writer and either replica after Protected(R) | Surviving copy plus independent recovery material reconstructs R, subject to the declared freshness gate |
| S04 | Multiple peer IDs share one failure domain; retention expires or probes fail | No inflated independent-copy count; protection status degrades visibly |
| S05 | Handover with pending work; stale old-epoch writes; network partition | One admitted writer; old epoch refused, conflict evidence retained, no automatic promotion |
| S06 | Counter, grant, tombstone or password conflict | No last-write-wins/CRDT merge; affected use freezes until explicit resolution |
| R01 | Original device/account unavailable; new clean device restores from independent material | Locate copies, verify full catalog, unseal exact records and reproduce expected public keys |
| R02 | Both replicas omit an entry/tail or serve the same old valid checkpoint | Completeness/freshness failure or FreshnessUnknown; never latest/empty success |
| R03 | Offline reserved HOTP/code/quota use followed by loss before sync | Whole unreconciled protected reservation treated as possibly used; no reissue/reset |
| R04 | Writer lost before local tail is protected | Restore/report only the evidenced recovery point and known uncertainty |
| R05 | Missing recovery factor, deleted ciphertext or corrupt wrapping key | Explicit unrecoverable/incomplete state; no regenerated substitute |
| R06 | Rotate key/provider, compact history or tombstone an entry; interrupt each boundary | A complete advertised recovery path survives; deleted entries do not reappear |
| M01 | Import legacy custody and compare known derivation/signature vectors | Exact existing subjects/bytes, durable reopen and independent restore before old readers retire |
| M02 | Two neurons/networks and worker/device changes share the same Vault | No scope collision, retargeting or accidental new subject |

Software tests cannot establish physical failure-domain independence, hardware
non-extraction or resistance to a compromised OS. Label the evidence type and
its limits rather than promoting those claims from a mock implementation.

## First product demonstration

1. Create a Vault with independently retained recovery material. Store synthetic
   passwords/PINs, external OTP enrollments, recovery codes, tokens and a spell.
2. Derive a neuron without exposing its key; perform approved credential/OTP
   uses, including a pre-reserved offline use with uncertain provider outcome.
3. Reach Protected(R), then restore-check R on a separate passive destination.
4. Destroy access to the writer and one replica. Recover from the remaining
   provider using only the advertised independent recovery prerequisites.
5. Verify every retained record, deletion, subject and conservative use-state
   barrier. Establish current authority/fencing before promoting the new writer.
6. Resume operations; reject the old writer's later stale-epoch update.

Repeat with omitted/stale/corrupt data and an unavailable freshness authority.
The correct negative result is part of the demonstration, not a skipped test.

## Measurements and evidence

Report local commit latency, time/bytes until Protected, replica catch-up cost,
full/incremental restore time, peak client memory, retained data overhead and
time to first permitted use. Separate crypto, disk, network, verification and
fencing delays. Include record counts/sizes, padded sizes, hardware/filesystem,
failure-domain deployment, cold/warm cache and configured concurrency.

State the protection lag and recovery-point exposure during offline/degraded
operation. No numeric speed, zero-data-loss or mission-critical readiness claim
follows from these contracts alone. A release names precisely which gates and
profiles passed, with unresolved limitations and migration/rollback behavior.
