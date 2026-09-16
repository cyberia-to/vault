# vault

**Your secrets survive your devices.**

Vault keeps the secrets of a person and their robot: neuron spells, private keys,
passwords, PINs, authenticators, recovery codes and service credentials. It lets
authorized applications use them, keeps private replicas, and restores them
when a device is lost.

Vault is a fundamental [soft3](https://github.com/cyberia-to/soft3) component and
the stack's first end-to-end storage and synchronization use case. It is also
the secret-custody organ of [cyb](https://github.com/cyberia-to/cyb), available
to headless hosts through the same contract.

**Stage: local custody library and CLI.** Rust code now stores typed secrets through
Cybergraph/BBG, reserves protected uses, verifies encrypted local replicas and
restores against an independently retained revision. The isolated native service,
production Ward adapter and authenticated network sync remain implementation work.
There is no packaged production release yet.

The library has no configured limit on total records or revisions. It stores
encrypted per-entry changes and reads history in pages; individual operations
retain resource bounds. Existing snapshot histories remain readable.

## What Vault should make possible

- **Keep everything that cannot be regenerated.** Imported passwords, external
  2FA enrollments and recovery codes have durable encrypted records. A spell is
  not their backup.
- **Use a secret without handing it to an agent.** Authorize a neuron action,
  produce an OTP code or authenticate to an approved service. Root spells and
  private keys stay inside custody.
- **Keep private copies you control.** Replicas retain encrypted content without
  gaining permission to read it or act as you. You can replace a storage provider.
- **Move to a new device.** Restore records and their use state, check the
  recovery point, and explicitly transfer authority to the new device.
- **Know what is safe.** See which changes are local, which have enough durable
  replicas, and which recovery point has actually passed a restore check.

## One ordinary journey

Create or import a secret through a protected entry surface. Vault saves it
locally, synchronizes encrypted records, and reports the revision protected by
your replica policy. An application then asks for a specific allowed use.

If the primary device is lost, a new Vault uses independently retained recovery
material to find and verify its encrypted copies. It restores the complete
selected revision, including OTP counters and recovery-code use. Missing or
older data is reported explicitly; an empty replacement Vault is never success.

| What you see | What it means |
|---|---|
| Saved locally | The selected device confirmed a durable commit |
| Protected through revision R | The configured independent replica policy has durable receipts for the complete recovery data at R |
| Recovery checked at R | An independent restore exercised that revision and its recovery material |
| Pending / degraded / conflict | Replication, freshness or writer agreement is unresolved; Vault names the affected revision |

Offline changes remain usable only within their explicit policy and are shown
as local until protected. An acknowledged old backup does not protect new work.
Data lost before replication cannot be recovered by a spell or a proof.

## How it fits

Ward decides whether an operation is allowed. Vault keeps the secret and performs
the permitted use. Mudra supplies cryptography. Cybergraph and BBG preserve its
encrypted history; the selected synchronization and transport services move
those encrypted records. Sigma manages neurons and assets. None of these roles
requires applications or models to receive a root secret.

One Vault can serve many neurons and networks. `derive_neuron` preserves existing
identity profiles. Passwords and authenticators need no neuron of their own.

## Read the design

Start with the [specification map](specs/README.md), then
[architecture](specs/architecture.md), [storage](specs/storage.md) and
[synchronization](specs/synchronization.md).

The first implementation target is one active custody writer, two independent
encrypted replicas, explicit device handover and recovery after loss of the
writer. [Conformance](specs/conformance.md) defines the gates;
[the roadmap](roadmap/README.md) orders the work. Concurrent offline writers
require a later qualified profile.

## Try the implemented slice

Build the local operator CLI (macOS/Linux; compatible sibling stack checkouts):

```sh
cargo build --release --bin vault --locked
./target/release/vault
./target/release/vault init --recovery-file /path/to/separate/recovery.factor
./target/release/vault add spell --label "Main neuron" --scope neuron
./target/release/vault add password --label "Mail" --scope mail --revealable
./target/release/vault list
```

The CLI asks for secrets with hidden terminal prompts. `spell` is the Cyber
name for recovery words/root material; imports preserve the existing BIP-39
derivation. Spells have no reveal/export command. Default storage is
`~/.cyber/vault`, backed by Cybergraph and BBG/Fjall.

Register two ciphertext destinations before protected use:

```sh
./target/release/vault replica-add --path /Volumes/backup-a/vault --failure-domain disk-a
./target/release/vault replica-add --path /Volumes/backup-b/vault --failure-domain disk-b
./target/release/vault sync
./target/release/vault checkpoint --out /path/to/separate/checkpoint.json
```

`show ID`, `otp ID`, `recovery-code ID` and `derive-neuron ID` reserve their
operation and verify both copies before delivering a result. Keep the printed
request ID when retrying an interrupted use. This is local operator custody;
the declared disk names do not establish physical independence by themselves.

[CLI guide](docs/cli.md) · [CLI contract](specs/cli.md)

With compatible sibling stack checkouts, run the synthetic recovery demonstration:

```sh
cargo run --release --example recovery --locked
```

It stores a test credential, verifies two encrypted copies, performs an authorized
use, removes the primary store and one replica, then restores read-only from the
remaining copy. It creates only temporary test data; all copies are on the same
test machine, so this demonstrates recovery logic rather than hardware
failure-domain independence.

[Library integration](docs/local-custody.md) ·
[Local profile](specs/local-profile.md) ·
[Evidence and remaining gates](audit/local-custody-2026-09-16/README.md)
