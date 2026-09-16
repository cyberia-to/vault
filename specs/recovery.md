---
title: recovery and device loss
status: draft
version: 0.1
---
# Recovery

Vault recovery reconstructs secret custody and protected-use state at an explicit
verified revision. A successful decrypt, known seed or collection of valid entries
does not establish complete or current recovery.

## Independent recovery material

The recovery profile MUST retain, independently of the primary device:

- sufficient authenticated locators/bootstrap credentials to reach replicas;
- the supported envelope/profile identifiers and trust anchors;
- an independent factor/quorum able to unwrap the required storage keys;
- the declared freshness mechanism and latest protected recovery reference
  available through that mechanism.

A sealed recovery capsule includes versioned key/derivation/epoch metadata and
the authenticated descriptors needed to recover the encrypted record closure.
It is restored directly into authorized custody. Its opening factor cannot be
available only inside that same lost Vault, nor can its sole location be an
unbacked cursor on the lost device. Replica login credentials must not introduce
the same circular dependency.

The factor is custody-level authority. Device unlock, neuron root seed, stored
service credentials and recovery material are different roles. No raw seed
export/copy operation is introduced. A future raw-mnemonic ceremony requires an
explicitly weaker export profile. An independent recovery factor may itself
require protected offline storage; losing every opening path makes otherwise
intact ciphertext unrecoverable.

## What survives a seed

| Material | Recoverable from a neuron seed alone? | Additional requirement |
|---|---|---|
| Deterministic derived neuron keys | Only with the original derivation profile/scope and necessary metadata | Locate the declared profiles and epochs |
| Imported passwords, OTP seeds and tokens | No | Durable encrypted entry records and storage-key recovery |
| HOTP counters, recovery-code use, quotas and revocations | No | Fresh authenticated state, surviving reservations and reconciliation |
| Hardware-bound non-exportable credentials | Not in general | Hardware-specific migration, provider re-enrollment or alternate authority |
| Payment notes and spendability | No | Retained ciphertext/openings and verified payment-history recovery |
| The complete robot | No | Name, Soul, Vault recovery material and Log under their owning contracts |

The [Mudra private-recovery contract](https://github.com/cyberia-to/mudra/blob/master/specs/private-recovery.md)
still defines private discovery, complete history coverage and spend-state
verification. Vault supplies its scoped keys. This design changes neither the
ledger's UTXO/account model nor its recovery-query cryptography.

## Restore protocol

1. Enter recovery through the protected surface. Pin the vault scope, profiles,
   independent trust/freshness reference and intended role.
2. Query available replicas using the portable descriptors. Verify authenticated
   manifests, writer/policy lineage and the pinned minimum revision. Retain
   conflicting evidence rather than choosing the newest timestamp.
3. Retrieve the complete closure for the selected checkpoint and tail. Check
   catalog completeness, tombstones, key epochs, use state and bounded decoding.
   Omitted/corrupt/unavailable objects are explicit failures.
4. Unseal in custody; reproduce expected public derivations and verify record
   schemas/state. Persist the complete restored result and receipts atomically.
5. Report the exact restored revision, its freshness/replication evidence and
   any unprotected tail or uncertain external operations. Begin read-only.
6. Activate only after current Ward authority, writer fencing, lease/reservation
   reconciliation and the required replica policy have been established.

A restore exercise uses an isolated test destination and never automatically
promotes a second live writer. Production recovery must be possible without
the original device, provider account or unbacked local metadata.

## Freshness and completeness

Complete recovery is always relative to an authenticated scope/revision. A
surviving device can pin its previously observed head. For total device loss,
the profile needs an independent current reference: for example a qualified
checkpoint/fencing service or a separately retained authenticated head with an
explicit age bound. The exact mechanism and trust/failure assumptions are a
profile prerequisite, not an implicit property of encryption or BBG openings.

A static recovery kit can establish an older lower bound; by itself it cannot
prove that no later protected update exists. Polling two replicas and choosing
their highest claimed sequence also cannot prove freshness if both withhold a
newer revision. Without the required current reference, the result is
`FreshnessUnknown` at the verified revision. It MUST NOT reset grants/counters,
claim the latest balance or silently become an active writer.

Availability is separate again: a proof of a valid checkpoint cannot recreate
missing ciphertext. If all copies of required data are lost, recovery reports
data loss. No new empty Vault or generated identity substitutes for the original.

## Loss, rotation and rollback

| Event | Required behavior |
|---|---|
| Writer lost after Protected(R) | Restore R from surviving complete copies, establish freshness/fencing, resolve reservations before activation |
| Writer lost with newer local work | Report protection only through R; never claim recovery of the lost tail |
| One replica lost | Fetch from another, degrade policy status and create/verify a replacement |
| All presented copies are stale | Detect against an independent reference or report FreshnessUnknown |
| Recovery factor lost | Use only a previously configured independent recovery path; no bypass |
| Device revoked | Refuse future admitted use; rotate future data keys/access and reconcile external credentials separately |
| Old snapshot restored | Preserve newer policy/tombstone/counter barriers from trusted freshness evidence; refuse activation if unresolved |
| Key rotation interrupted | Recover a coherent key/record generation; retain the last proven recovery path until replacement succeeds |

Recoverability MUST be exercised before retiring the only prior usable copy or
key wrapper. Sealed backups alone do not synchronize mutable state. Any automatic
cleanup needs evidence that the replacement recovery closure remains complete.
