---
title: typed secrets and protected operations
status: draft
version: 0.1
---
# Typed secrets

A secret record has a versioned kind/schema, random opaque `SecretRef`, purpose,
applicable subject/service/network scope, allowed operations, Ward policy
reference, disclosure rule, custody/recovery profile and lifecycle revision.
Payload and sensitive metadata MUST be encrypted. A `KeyRef` is a restricted
secret reference; possession of a reference grants no authority.

| Kind | Normal operation | Permitted disclosure |
|---|---|---|
| Root seed / mnemonic | Generate/import; derive purpose-scoped keys and neurons; sealed backup | No raw read/reveal/copy through application APIs |
| Private signing / authority key | Authorize an exact action or approved proof | Authorization/proof result only |
| Discovery / payload / channel / wrapping key | Purpose-bound agreement, discovery, seal/open or wrapping | Declared results only; internal storage keys cannot serve generic decryption |
| Password / PIN | Deliver to the bound service/device | Recipient receives the value; trusted reveal/export requires a separate explicit grant |
| TOTP / HOTP authenticator | Generate a code under a pinned algorithm/parameter profile | Code only during normal use; enrollment transfer requires a sealed migration profile |
| Recovery-code set | Reserve/release a code for its provider | One logical authorized release with durable use state |
| API token / service credential | Authenticate through a bound adapter | Approved audience receives the necessary credential; no implicit agent/model disclosure |
| Passkey credential | Produce an assertion for a relying party and challenge | Assertion only; portability follows the actual custody profile |

Kind, permission and custody level are separate. Retagging a seed MUST NOT enable
password reveal. Unknown kinds or versions fail closed. Extensions require a
reviewed schema and operation set, not arbitrary plugins running with secrets.

"2FA" names a role in an authentication policy, not one record format. A stored
service password/PIN differs from a Vault unlock factor. Low-entropy factors
cannot supply root-key entropy; an unlock profile must resist offline guessing
and enforce its attempt limits. Password and OTP stored in one compromised
Vault are not independent custody factors.

## Operation sketches

```text
create/import(kind, protected input, policy) -> SecretRef + permitted descriptor
derive_neuron(KeyRef, derivation_profile, scope, selector, grant, request_id)
    -> KeyRef + SubjectRef + permitted public descriptor
authorize_action(KeyRef, canonical intent, grant, request_id) -> authorization
open_message(KeyRef, bound ciphertext, grant, request_id) -> permitted content
prove_authority(KeyRef, approved relation, public inputs, grant, request_id) -> proof
otp_code(SecretRef, bound request, grant, request_id) -> code
deliver_credential(SecretRef, bound destination, grant, request_id) -> receipt
reveal_entry(SecretRef, protected output surface, grant, request_id) -> permitted entry
lock / revoke / rotate / backup / restore under authenticated lifecycle policies
```

These are logical operations, not an implemented or frozen wire API. There is
no generic secret dump, unrestricted signing oracle, derivation callback or
storage-key decrypt endpoint. Authentication assertions specialize the same
exact-intent interface rather than expose private keys.

## Deriving neurons

`derive_neuron` resolves keys and subjects deterministically under an explicit
profile. The same root/profile/scope/selector MUST preserve the key and subject
association across devices. Existing Cosmos paths, domain derivations, native
IDs and signature bytes remain unchanged.

Native profiles return `Native(NeuronId)`; supported foreign profiles return
`Foreign(domain, address_bytes)`. There is no invented hash/cast of a foreign
address to fit the native shape. Derivation creates no grant, attachment, active
selection or ledger record; Sigma/host composition owns attachment management.
Rotation of a key-derived subject requires the original key or an explicitly
specified authority transition to retain the subject.

Generation, mnemonic parsing and HD derivation execute behind custody. Low-level
arithmetic may live in Mudra; callers stop receiving raw keys from those helpers.
Mudra's [private programmable authority](https://github.com/cyberia-to/mudra/blob/master/specs/identity.md)
can use the same boundary through a qualified private-proof profile. Moving
custody does not select a new signature, hash or identity scheme.

## Lifecycle and external services

Creation, import, replacement, suspension, revocation and tombstoning are durable
transitions. Deletion from the active view preserves the retention/recovery
rules; it cannot erase copies already disclosed to another device or provider.
Changing a password remotely is a separate external action from storing a new
candidate locally. An uncertain provider result cannot be reported as a completed
rotation; retain enough protected state to reconcile it.

Imported external credentials are irreducible data. The first-use/rotation
default requires their containing revision to meet [replication policy](synchronization.md)
before external activation. Ward may authorize an explicit offline exception,
whose result remains visibly local and at risk of device loss. A manually
performed external enrollment outside Vault cannot inherit a retention guarantee.

OTP profiles pin parameters and time/counter authority. Callers cannot request
arbitrary future time steps or rewind HOTP. TOTP may repeat within a time window;
Vault cannot guarantee one-time acceptance at an external provider. HOTP and
recovery-code use require durable reservations and [retry rules](authorization.md).
