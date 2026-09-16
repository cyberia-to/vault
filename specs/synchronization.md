---
title: private synchronization and replicas
status: draft
version: 0.1
---
# Private synchronization

The initial `single-writer-replicated-v1` profile synchronizes one authenticated
Vault history to encrypted replica stores. Vault defines record/recovery policy;
Cybergraph and the selected stack adapters supply history transfer, conditional
admission, framing and transport. A new Vault-specific P2P or consensus engine
is not required by this contract.

## Roles

| Role | Has | Does not acquire implicitly |
|---|---|---|
| Active custody writer | Unlocked approved keys, current Ward authority and a fenced writer epoch | Permission to export roots or bypass protected-use rules |
| Replica store | Ciphertext, minimal routing/authentication metadata and a retention obligation | Decryption, neuron signing or authority to change Vault history |
| Restoring device | Independent recovery material and verified encrypted records | Active writer status or revived historical grants |
| Enrolled read-only device | Its explicitly scoped access and verified selected revision | Mutation, protected-use quotas or automatic writer promotion |

A replica can run on another user device or a storage service. Another device
holding a copy is not necessarily an authorized custody endpoint. Enrollment
binds the peer/channel, role, disclosed keys, scope and epoch through an approved
ceremony; an endpoint string or copied `VaultRef` is insufficient.

## Protection policy

The initial target requires a durable local writer and at least two replicas in
distinct configured failure domains, excluding that writer. Multiple paths,
processes or peer IDs on one disk/provider do not establish independence.
Failure-domain classification is explicit deployment evidence, not something
a signature or content proof establishes on its own.

Each replica receipt binds the logical vault scope, exact revision/manifest,
complete closure commitment, writer/profile epoch, replica identity, request,
retention terms and authenticated acknowledgement. A receipt can be counted only
after the receiver validates the authorized lineage and confirms that every
required encrypted object is durable under its advertised storage contract.
Transport delivery, a cached root or an open socket is not a storage receipt.

`Protected(R)` survives loss of the writer and one replica only if the remaining
copy actually retains the complete closure and recovery material survives.
Receipts are authenticated promises; qualification tests, readback/restore
probes and any separately selected storage-proof profile establish evidence of
ongoing retention. No proof can force a provider to respond in the future.

## Transfer and acceptance

1. Pin the expected vault scope, profile, writer epoch and known head or recovery
   anchor. Authenticate the peer and permitted replication role.
2. Exchange bounded manifests/inventories and fetch missing ciphertext. Staging
   MUST NOT advance a visible head or an authenticated recovery cursor.
3. Check the exact predecessor or checkpoint lineage, ciphertext identities,
   manifest completeness, limits and admission authority. Reject corruption,
   unsupported profiles and conflicting histories distinctly.
4. Publish the complete revision/receipt atomically through the existing store
   owner. Send a storage acknowledgement only after durable commit.
5. The sender records verified receipts durably and advances protection status
   only when the configured policy is met. Retrying a request is idempotent.

Interrupted transfers resume by authenticated content/revision identity, with
entry/byte/memory/time budgets. Unavailable content yields an incomplete result;
it cannot advance the selected revision. A sender must retain enough local or
protected data to finish pending replication.

## One writer, explicit handover

Only one device holds mutation/protected-use authority in a writer epoch.
Every accepted mutation binds that epoch, predecessor and request identity.
The shared local BBG lock does not coordinate writers on different machines.
Encryption and synchronized files also do not provide distributed exclusion.

A normal handover drains/reconciles pending uses, protects the final source
revision, records relinquishment and a successor epoch through the selected
authenticated fencing authority, and verifies the destination's closure before
activation. Old-epoch writes are then refused by conforming admission points.
Fencing is a host/synchronization contract with an explicit trust model; Vault
MUST NOT describe a local epoch increment as distributed consensus.

If the old device is unreachable, recovery promotion requires a qualified
freshness/fencing mechanism and resolution or expiry of its allowed offline
lease. Otherwise restore is read-only. An owner clicking "replace device" cannot
cryptographically erase keys or stop an isolated old device from presenting an
already issued signature or password to an external service.

The first profile allows offline local work only on the current writer within
its lease. Other devices cannot create competing authoritative histories. If
two authenticated successors are observed, retain both as conflict evidence,
freeze affected authority and reconcile explicitly. No timestamp-based winner,
last-write-wins merge or generic CRDT may resolve passwords, counters or grants.

## Revocation, rotation and retention

Device revocation updates current admission and future access. To exclude a
device that knew data keys from future content, rotate the relevant keys/epochs;
rewrapping an unchanged key is insufficient. Revocation cannot unlearn previous
plaintext, keys or external credentials. External credential rotation and neuron
authority transitions follow their own verified protocols.

Provider replacement first populates and verifies a new complete replica, then
retires the old obligation. Retention/garbage collection MUST retain the current
advertised recovery points, their wrapped keys, tombstones and required tails.
A checkpoint digest without its ciphertext closure is not an archive.

Restore/import preserves counters and uncertainty barriers. Replicas MUST NOT
resurrect tombstoned records or re-enable consumed codes by replaying old snapshots.
If all stores present a consistent stale history, local authenticity alone
cannot reveal the omission: [recovery freshness](recovery.md) is a separate gate.

## Privacy and provider independence

Plaintext entries, service labels, seeds and reusable view/spend keys never reach
replicas/relays. Store-facing IDs SHOULD avoid publishing neuron or service
associations. Stable ciphertext equality, lengths, access times and peer addresses
may still correlate activity; the profile declares this leakage and its padding.

Recovery descriptors include portable authenticated locators and enough format
information to retrieve and verify copies without the original client account.
No sole server-issued secret cursor or login credential held only inside the
lost Vault may be needed to fetch it. Authentication to a replacement provider
uses an independent recovery/bootstrap path.
