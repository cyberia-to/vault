# Vault evidence

This directory holds source reviews, measurements, fault/recovery results and
release qualifications. It is separate from the contracts in `specs/`.

## Design provenance — 2026-09-16

The owner established a dedicated Vault repository and made safe durable storage
and synchronization the first soft3 use case. This design incorporates the
earlier custody proposal and its architecture review from soft3 `4ddfab4`:

- [Custody proposal at the reviewed revision](https://github.com/cyberia-to/soft3/blob/4ddfab48f81f5df9cb3dcb0ed9b5da3d0001d7de/proposals/vault-secret-custody.md).
- [Existing custody source audit](https://github.com/cyberia-to/soft3/blob/4ddfab48f81f5df9cb3dcb0ed9b5da3d0001d7de/audit/vault-custody-2026-09-16.md).
- [Architecture alignment review](https://github.com/cyberia-to/soft3/blob/4ddfab48f81f5df9cb3dcb0ed9b5da3d0001d7de/audit/vault-architecture-alignment-2026-09-16.md).

Local source contracts additionally inspected for this design:
`bbg/specs/database.md`, `bbg/specs/application-storage.md`,
`bbg/specs/storage.md`, `cybergraph/specs/native-storage.md`,
`soft3/specs/execution-model.md`, cyb anatomy/parts, and Mudra's identity/private
recovery contracts. Some adjacent repositories contain concurrent uncommitted
work; this repository does not publish or certify those changes.

The older soft3 sync/tape proposal references a separate `sync` repository absent
from this checkout and has unresolved ownership wording. Vault therefore binds
to a selected stack synchronization/fencing profile rather than declaring that
proposal's specific adapter already exists. The first profile must select and
qualify the real adapter; native local BBG/Cybergraph commits alone do not supply
distributed fencing, private replication or current recovery anchors.

## Evidence status

This initial repository contains product/specification documents only. No Vault
runtime tests, private sync benchmark, power-loss test or restore drill has run
as part of this change. The conformance matrix is a set of required future tests.
No real seed, key, password, OTP enrollment or recovery file was opened or imported.

Document validation passed for the initial design: 12 Markdown documents,
18 local link targets, six GitHub contract paths mapped to sibling source files,
balanced code fences/table columns, draft spec labels, Git whitespace checks
and the stack's NTFS filename check. This checks document structure and local
source references, not runtime behavior or remote service availability.
