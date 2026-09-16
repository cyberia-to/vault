---
title: authorization and protected use
status: draft
version: 0.1
---
# Authorization

Ward is the sole permission authority configured by Soul. Vault MUST authenticate
each caller and enforce an exact, current Ward decision at the operation boundary.
It may run the shared evaluator inside custody or verify an authenticated decision
with a specified freshness/revocation protocol. It MUST NOT mint a parallel set
of grants or accept an application-supplied `approved=true`.

## Exact request

A request binds secret/purpose, authenticated caller, operation, canonical inputs,
requested disclosures, destination/output surface, policy revision, request ID,
expiry and limits. Neuron actions additionally bind subject/binding revision,
key profile, program, network/genesis and action bytes. Pure local secret
management invents no network or neuron. Credential delivery binds the actual
audience/origin; redirects or origin changes require renewed authorization.

The adapter MUST reconstruct the statement being authorized. A naked digest
without trusted interpretation of the action is insufficient. Only approved
proof relations and public-output schemas may use a private witness; arbitrary
circuits could output the secret.

Handles and persisted selection are not grants. Delegation only attenuates;
custody restrictions may narrow a Ward grant, never widen it. Policy and grant
changes require authenticated lifecycle authority and durable revision tracking.
Decision credentials and protected confirmation belong to the declared trust
boundary, not to an ordinary application that can approve its own requests.

## Permission and service state

| Service state | Allowed behavior |
|---|---|
| Locked | Bounded ciphertext replication/status; authorized unlock/recovery ceremony; no secret use |
| Verified read-only | Inspect permitted restored data/metadata; no protected external use or authoritative writes |
| Active writer | Authorized operations and durable transitions within the current fenced writer epoch |
| Frozen / conflict | Diagnose and reconcile; no dependent secret release or mutation |

"Read-only" does not grant password reveal or signing. In the initial profile,
protected uses with receipts, counters or quotas go through the active writer.
Unlocking storage alone does not promote a device or revive an expired grant.

## Durable operation protocol

1. Authenticate the caller and check kind, purpose, exact intent, Ward decision,
   current policy and writer epoch, limits and applicable replication barrier.
2. Atomically reserve permission/quota and protected-use state under a request
   identity bound to the complete intent. A conflicting reuse is rejected.
3. Perform the approved private operation in the selected custody boundary.
4. Durably record its result or explicit uncertain outcome before reply/release.
   Retained secret-bearing results are encrypted and access controlled.
5. Deliver only the permitted result to the bound recipient. External acceptance
   requires its own evidence; a local delivery receipt proves no login or payment.

An exact retry retrieves/reconciles the original operation; it does not consume
a second code or counter. Result replay still requires current authority and
disclosure checks. A request ID never becomes a perpetual credential. Failure
at a commit boundary freezes dependent work until the owner reopens and resolves
the durable receipt. An unknown external result is not safe to repeat blindly.

HOTP reservations advance a counter durably before release. Recovery codes have
available, reserved, consumed and uncertain states. A timeout or restore cannot
make an exposed code unused. The use-state protection profile MUST either protect
the reservation remotely before an irreversible release or have an independent
freshness/reconciliation mechanism preventing restored reuse. Offline use may
consume a pre-reserved range/set and quota lease already protected on replicas.
After loss of the writer, every unreconciled reservation is treated as possibly
used; recovery skips/burns it and applies the provider's resynchronization rules.
An uncertainty marker held only on the lost device supplies no protection.
Without a surviving reservation or equivalent evidence, this offline use MUST
be refused. Recovery need not know which reserved codes were actually accepted.

## Revocation and offline work

The profile defines a linearization point between revocation and protected use.
Revocation blocks later admitted operations; it cannot retract a signature,
password or code already delivered. Neuron checks permission again at effect
dispatch; receiving protocols enforce their own replay and admission rules.

Offline automation requires an explicit bounded lease, a qualified time/epoch
source and retained quotas. A policy cannot promise both unrestricted offline
use and immediate remote revocation. The initial profile MUST report its maximum
revocation delay and refuse operation when it cannot establish lease validity.
Policy rollback protection cannot rely solely on an older encrypted file.

## Protected interaction

Creation/import/recovery secrets enter through a controlled surface directly
into custody. They MUST bypass generic chat capture, model context, argv,
environment, terminal history, ordinary UI state and logs. Com can route an
explicit protected-entry mode; pattern matching arbitrary chat cannot establish
universal interception.

Revealable entries/codes use a separately authorized output surface. Clipboard
copy is a disclosure permission with recipient/retention implications, never an
inherited spell operation. Errors, telemetry, crash reports and debug formatting
MUST omit secret content. Memory protections and zeroization have their declared
platform limits; they do not establish security against a compromised OS.
