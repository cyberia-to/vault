# Native signing inside custody

`sign(context, request_id, SignRequest, ward)` prepares a protected use and
returns `PendingUse`. `SignRequest` binds the exact `NeuronKeyRef`, native
32-byte subject and 32-byte canonical action statement. Only spell/Cosmos and
domain-root/domain derivations are supported. The key must own the requested
subject. No private key or root is returned to the caller.

The signature profile is Mudra's existing [NSIG1](../../mudra/specs/neuron-auth.md):
`NSIG1 || compressed_public_key[33] || ADR036_signature[64]`. The signed message
is `cyber:neuron:authority:v1:` followed by the statement bytes; the ADR-036 signer
always uses the literal `neuron` HRP. A key reference's address HRP does not change
the signature domain, native ID or existing signature bytes. This is the existing
secp256k1 profile; selecting a future signature suite requires a separate contract.

The host reconstructs the canonical statement from the action, authenticates its
caller and checks current subject/network/policy/epoch/program/act rights. Vault's
typed request binds that decision to the exact key, subject and statement. A hash
submitted by an untrusted program is insufficient authority. The local CLI is an
explicit operator command inside the trusted host; it is not a remote signing API.

Signing uses the normal prepare/replicate/release protocol. Before output leaves
custody, the encrypted receipt must commit, two configured replicas must cover
that revision and Ward must authorize release. The result is
`Output::Signature { request, evidence }`. Exact request retries return the
original receipt and signature, including after reopen; changed inputs conflict.
Revocation, entry replacement/deletion, stale anchors, read-only recovery, missing
copies and uncertain commits block release. Every request ID is independently
random; a public action digest must not become a store-visible request ID.

Encoding adds operation tag **6**: root[16], the existing derivation encoding,
subject[32], statement[32]. Output tag **3** follows the existing timestamp and
contains a length-prefixed encoded Sign operation and exactly 102 evidence bytes.
Tags 1–5 and previous output encodings remain unchanged. Unknown tags and trailing
bytes reject; old clients must upgrade before reading a signing receipt.

Hosts retain independent anchors and reconcile uncertain writes as specified in
[the local profile](local-profile.md). Neuron's custody adapter delegates to this
protocol, while its authority guard covers the complete signing call and its
publication/dispatch guard checks permission again. A released signature records
an authorized decision; it cannot override later revocation.
