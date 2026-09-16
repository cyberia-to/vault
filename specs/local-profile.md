---
title: local custody implementation profile
status: local-library-profile
version: 2
---
# local-custody-v2

This bounded first implementation supplies the custody/storage library and a
Cybergraph adapter. It runs inside a trusted host; it does not yet supply the
isolated native service, authenticated network transport, distributed fencing
or a production Ward adapter. It MUST NOT advertise the complete
single-writer-replicated-v1 deployment profile.

## Types and operations

| Type | Permitted use in this profile |
|---|---|
| Password, PIN | Reveal on an approved surface if explicitly revealable; deliver to the exact recorded destination |
| Service token | Deliver to the exact recorded destination; no generic reveal |
| TOTP | Generate a code using Ward's trusted time; reject release outside its original window |
| HOTP | Reserve and persist the next counter before code release |
| Recovery codes | Reserve an unused code before release; exact retries retain the original reservation |
| BIP-39 spell | Import through the trusted host; derive existing Cosmos-path public credentials inside custody |
| Domain root | Generate inside custody; derive existing Mudra domain public credentials inside custody |

`derive_neuron` returns the native `H(compressed_public_key)` subject, public key
and existing compatibility address. A Cosmos address is not a foreign subject or
a proof of external account control. [`sign`](sign.md) signs native action
statements under the existing Mudra NSIG1 profile through the same protected-use
protocol. Foreign binding, passkeys and raw key import need separate typed
adapters. There is no raw root/private-key getter.

## Encoding and limits

One committed Blob contains one encrypted record change and its operation
receipt. Its application namespace is a random 32-byte VaultId. There is no
configured ceiling on the total number of live entries, tombstones or revisions.
The existing u64 history position remains the wire representation, with checked
overflow. Available storage and host resources determine practical capacity.
Application heads and content IDs use existing Cybergraph/Hemera codecs.
Integers are little endian; variable fields have u32 byte/count lengths;
unknown versions, duplicate/out-of-order IDs and trailing bytes reject.

Individual secret values are at most 16 KiB, with bounded 256-byte labels,
1024-byte scopes and 64 recovery codes per enrollment. A packet is bounded by
4 MiB; plaintext reserves 1024 bytes within that limit for the envelope. These
are per-operation decoding budgets, never total catalog/history limits.

The outer authenticated `CVLT1` packet encoding and key-wrapping bytes stay
unchanged. New plaintext records use `VSTATE2`: the existing request/fingerprint/receipt
fields, then one change tag: genesis (0), put/replace (1), delete (2), protected
use/reservation (3). Put/use carries one canonical Entry; delete carries one
SecretRef. Genesis is valid only at index zero. Entry versions advance on
replacement, while use preserves the version and durably updates its use state.
Each commit's predecessor authenticates the complete ordered change history.

Reopen streams history pages and reconstructs an index of current encrypted-entry
locations and tombstones; it does not retain all plaintext secrets or all history
positions. A current entry is decrypted on demand. Mutation writes only the
affected entry and receipt. Retained bytes grow with actual committed changes,
not catalog size multiplied by every operation. No compaction is introduced.

Existing `VSTATE1` snapshots remain readable with their original ciphertext,
requests and identities. A legacy history may append v2 changes without rewriting
its prefix. A v1 snapshot after the first v2 record is rejected as a downgrade.
Older clients cannot read v2 payloads and must be upgraded before using that tail.

The envelope exposes VaultId, random RequestId, revision/predecessor, wrapping
descriptor and ciphertext length. Hosts MUST use independent random request IDs,
never secret-derived or identifying values. Record labels, scopes, types and
receipts are encrypted. This profile does not hide access timing, total size or
revision linkage from a store/transport observer.

Only encrypted packets are content addressed. A keyed request fingerprint
inside each packet binds the full operation, actor, policy and input secret;
it never exposes a dictionary-testable password hash. Application receipts map
request IDs to the original revision so exact retries survive later writes.
Historical result release still checks current authority and entry version.

## Cryptographic envelope

Use the existing XChaCha20-Poly1305 family through RustCrypto, with OS-generated
32-byte storage keys and independent random 24-byte nonces. Fixed version/domain,
VaultId, revision, predecessor and bootstrap descriptor are authenticated data.
Plaintext buffers and owned secret payloads use zeroizing storage; debug/error
messages contain no input values. Third-party derivation internals retain their
own memory-handling limitations pending native custody qualification.

Two independent factors wrap the same storage key: an unlock passphrase through
Argon2id v0x13 (65536 KiB, 3 iterations, 1 lane, random 16-byte salt), and an
independently retained 32-byte recovery factor through a separate wrapping
domain. KDF parameters are fixed by this profile, never attacker-selected. Input
lengths are checked before derivation. This is not a PIN-only unlock profile.
HMAC-SHA256 derives the request-fingerprint key in its own domain. Concrete
encodings are defined by the bounded encoder/decoder and golden tests.

References: [RustCrypto AEAD](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/),
[Argon2](https://docs.rs/argon2/0.5.3/argon2/),
[HOTP](https://www.rfc-editor.org/rfc/rfc4226.html) and
[TOTP](https://www.rfc-editor.org/rfc/rfc6238.html).

## Authority and release

The trusted host supplies a Ward port whose authorization guard covers the full
operation/publication or result delivery. Vault supplies the exact typed intent;
it supplies no allow-all implementation. This interface is not an untrusted IPC
protocol or independent authentication of a caller-supplied identity.

Protected use first persists an encrypted result/reservation. Plaintext delivery
requires verified copies of that exact revision on two distinct configured local
replica stores, then a fresh Ward guard. Failure after reservation never reuses
a code/counter. An exact retry reuses the encrypted original receipt. In this
profile there is no unprotected offline one-use release or lease allocation.

Local copy verification uses Cybergraph commits and readback. Its result is
explicitly local evidence, not an authenticated remote provider receipt or proof
of physical failure-domain independence. The host supplies failure-domain labels.
Ciphertext transfer works without unlocking; replayed/divergent prefixes reject.
The local helper iterates application history itself; it is a development
implementation, not the shared live synchronization adapter required by the
[deployment contract](synchronization.md#shared-graph-boundary). Each validation
walk reads the complete retained history in bounded pages, even when only new
packets are copied. Page size limits one read, never the Vault's lifetime.
Missing, repeated, reordered or extra history rows reject.

Open and restore require an independently supplied exact Revision anchor and
verify the complete contiguous history to it. An older or newer selected store
head is rejected rather than inferred fresh. A recovery-factor restore is
read-only; it cannot promote a writer. No recovery-factor or raw-root export
getter is exposed. The host retains factors/anchors separately through its
protected ceremony. Real user custody migration is outside this first profile.

An uncertain mutation freezes the session. `pending_commit()` identifies the
locally prepared candidate revision; the host retains it and the prior anchor,
resolves the durable request receipt, closes the old store and reopens against
the matching retained anchor. It MUST NOT blindly retry with a new request ID.
An uncertain initial creation has no returned session/candidate anchor; it
requires explicit reconciliation by the trusted host and MUST NOT be presented
as a successfully created or safely replaceable Vault.
