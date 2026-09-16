# Implementation order

The current deliverable is this repository's product and specification design.
Implementation follows after that baseline. Each package produces reviewable
code and evidence in `audit/`; an API name or stub is not completion.

| Package | Work | Exit evidence |
|---|---|---|
| A — pin the first profile | Canonical schemas/encodings and bounds; crypto/envelope/KDF profiles; OS isolation and protected input; Ward freshness; replica receipt and fencing/recovery-anchor choice | Versioned profile covers every open boundary in specs/README; threat and failure assumptions explicit |
| B — local custody and durable records | Typed service/client boundary, Mudra adapters, Cybergraph/BBG transactions and reopen; synthetic fixture imports; protected operations and reservations | C01–C05, D01–D03 and identity compatibility; no raw key path to applications |
| C — encrypted replication | Existing stack transfer adapter, complete-closure receipts, protection status, portable locators and retention | S01–S04 with interrupted transfer, provider loss and false acknowledgements |
| D — recovery and authority transfer | Independent capsule opening, checkpoint/tail verification, freshness, writer handover/fencing and offline reservation recovery | S05–S06 and R01–R06; complete device-loss demonstration |
| E — product integration and qualification | Replace cyb/Neuron legacy custody clients, expose protection states, explicit migration, backend/platform fault qualification | M01–M02, D04, measured end-to-end gates and a scoped release |

Implement packages B–D first against isolated synthetic stores. Do not migrate
real user custody until reopen, independent restore and compatibility gates
pass. Preserve original recovery material and legacy ciphertexts during explicit
migration; do not claim deletion from SSDs or backups.

Later profiles may add concurrent devices, hardware-native custody, passkeys,
private proving, threshold recovery and stronger traffic privacy. They must
preserve the typed-secret, durability and evidence contracts. They are not
prerequisites for demonstrating the first storage/recovery use case.
