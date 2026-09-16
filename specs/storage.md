---
title: encrypted durable storage
status: draft
version: 0.1
---
# Durable storage

Vault stores encrypted application records through Cybergraph over one existing
BBG Database owner. A separate plaintext seed file, second database writer or
independent Vault history/WAL is not part of this design. The SSD working profile
uses BBG's Fjall path; an explicitly selected HDD/archive profile uses redb.
Backend choice belongs to the shared owner. RAM-only success is not durable.

## Envelope and keys

Use a high-entropy storage key independent of neuron seeds, with versioned
authenticated encryption and a nonce policy qualified for retries, restore and
multiple device epochs. Each envelope binds its logical vault scope, object,
kind/schema, purpose, cryptographic profile, key epoch and revision against
substitution. Authentication of an envelope alone proves neither permission
to advance history nor that it is the latest revision.

Root seeds, entries, service names, subject associations, policy-sensitive
metadata and protected-use receipts MUST be sealed before reaching the store.
Content addressing applies to ciphertext. Unkeyed hashes of passwords, PINs or
other low-entropy plaintext MUST NOT become public IDs, request fingerprints or
deduplication keys. A profile states exactly which headers/lengths remain visible.

Device/unlock and independent recovery mechanisms wrap the storage key under
separate declared policies. Passphrase profiles require a salted memory-hard
KDF and measured parameters; a low-entropy PIN alone cannot protect a copied
database against offline guessing. Unlock MUST NOT require the same locked seed.
Key separation also covers storage, replication authentication, recovery and
neuron authority. Cryptographic algorithms remain Mudra/profile responsibilities.

## Complete revision

A revision binds a logical history position, predecessor, writer/device epoch,
schema/key epochs, request identity and a manifest of required encrypted content.
Its protected manifest covers the complete record catalog, entry versions and
tombstones, relevant policy references, counter/use state, derivation metadata,
wrapped keys and recovery descriptors. Header/manifest authentication binds all
parts. Concrete field encodings and size limits are profile parameters.

A checkpoint materializes one exact revision. It MUST authenticate the complete
catalog and its required content closure, with sufficient history/evidence to
validate that checkpoint and its tail. A set of valid individual entry envelopes
does not prove that no entry, deletion or counter transition was omitted.

Large content MAY be staged as immutable ciphertext in bounded chunks. Activation
MUST atomically publish the manifest/head, request receipt, relevant reservations
and retention pins only after all required chunks are durable. A pointer to
unavailable content is not a complete commit. Orphan staging may be collected
only after it cannot be referenced by an unresolved commit or recovery point.

The logical closure belongs to the application; Cybergraph validates it and BBG
supplies conditional atomic publication. A local head/hash is not a global BBG
polynomial proof, network consensus result or a guarantee of replication.

## Commit and reopen

Requests bind full canonical content and the expected predecessor/epoch. An exact
retry returns its original receipt even after later revisions; changed content
under the same ID conflicts. Conditional checks, content/head publication and
receipt retention share the same owner transaction and backend durability barrier.

Before publication, errors leave the previous selected revision intact. A backend
`CommitUnknown` freezes all dependent views. Reopen the shared owner and resolve
the request against durable receipts before retry, release or sync advertisement.
Unknown outcome MUST NOT be reported as either safe failure or successful storage.

Reopen validates versions, policy/writer lineage, contiguous history or a verified
checkpoint/tail, complete closure and receipt consistency under bounded reads.
Missing/corrupt/unsupported data is distinct from absence. It never causes silent
creation of an empty vault, replacement identity or test-key fallback.

## Protection states

| State | Evidence and scope |
|---|---|
| LocalCommitted(R) | Actual local backend durability for complete revision R |
| Protected(R, policy) | Required authenticated durable replica receipts covering the complete recovery closure of R, under the named retention/failure-domain policy |
| RecoveryChecked(R, time) | Independent restore of R verified closure, decryption, records, use state and recovery prerequisites |
| Pending / Degraded / Conflict / Unknown | The specific missing, expired, conflicting or unresolved evidence |

These facts are separate and revision-specific. New local work does not advance
the protected revision. A receipt describes a store's acknowledgement under its
trust contract; retention audits and restore probes measure continuing access.
Expired retention or failed probes MUST degrade the relevant status. Old receipt
bytes cannot keep a failing provider marked healthy indefinitely.

## Retention and deletion

Local cache eviction, archive compaction, device removal, key rotation and
provider replacement MUST preserve all advertised recovery closures. Keep the
last proven recovery point until its successor is durably protected and verified.
Tombstones prevent deleted entries reappearing from old replicas. Historical
ciphertexts remain subject to explicit retention and secure-disposal limits.

Deleting a local file does not erase SSD/backups or remote copies. Cryptographic
erasure is limited by retained keys and previously disclosed material; destroying
the sole decryption path intentionally destroys recovery and requires a distinct
lifecycle decision. Ciphertext/private namespaces never imply public publication.
