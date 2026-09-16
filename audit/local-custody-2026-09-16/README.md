# Local custody implementation — 2026-09-16

Vault now has a working Rust library for the bounded
[local-custody-v1 profile](../../specs/local-profile.md). It stores encrypted typed
secrets in the existing Cybergraph/BBG application path, reserves protected uses
before release, verifies local replicas and restores an independently anchored
revision. This is implementation evidence, not a production qualification.

## What the implementation covers

| Boundary | Implemented behavior | Evidence |
|---|---|---|
| Typed custody | Password, PIN, service token, TOTP, HOTP, recovery codes, BIP-39 seed, domain root; roots cannot be revealed/delivered or retagged | [Custody tests](../../tests/custody.rs), [input bounds](../../tests/input_bounds.rs) |
| Existing identity profiles | `derive_neuron` keeps Mudra's Cosmos-path/domain derivation bytes, native subject, public key and compatibility address | [Identity tests](../../tests/otp_identity.rs) compare the existing Mudra implementations |
| Authorization | Exact intent, actor/policy binding, current Ward guard held through mutation/delivery; replacement/deletion invalidates pending outputs | [Custody tests](../../tests/custody.rs), using an explicit synthetic Ward |
| Durable history | Complete encrypted snapshots, atomic expected-head commit, request deduplication, tombstones, reopen, shared BBG owner | [Recovery/fault tests](../../tests/recovery_faults.rs) on real Fjall stores |
| Protected use | Persist the original output and HOTP/recovery-code reservation; require two verified copies; exact retry returns the original result | [OTP tests](../../tests/otp_identity.rs), [restart tests](../../tests/recovery_faults.rs) |
| Local encrypted copies | Verify all history and content by readback; resume an interrupted prefix; reject forked history and acknowledgements without retention | [Recovery/fault tests](../../tests/recovery_faults.rs) |
| Independent restore | Password or independent recovery factor, exact trusted anchor, full history authentication; recovery-factor restore remains read-only | [Recovery/fault tests](../../tests/recovery_faults.rs), [demonstration](../../examples/recovery.rs) |
| Encoding/crypto checks | Frozen genesis encoding, hostile lengths/truncation/trailing bytes, every packet byte tampered, wrong key, randomized encryption, RFC OTP vectors | Unit tests in [state](../../src/state.rs), [crypto](../../src/crypto.rs) and [OTP](../../src/use_secret.rs) |

The secret-use callback executes inside the Ward authorization guard. A pending
handle is a receipt reference, not authority. Secret inputs/results use zeroizing
owned buffers and redacted debug/error output; private roots have no getters.
The metadata-only recovery check decrypts and validates all supported record
types without promoting the restored store or releasing their contents.

## Executed checks

| Command | Result |
|---|---|
| `cargo test --release --all-targets --locked` | 27 tests passed on the default GraphStore/Fjall path |
| `cargo test --release --no-default-features --locked` | 6 tests passed with the Cybergraph adapter disabled |
| `cargo run --release --example recovery --locked` | Saved, replicated, used, removed primary and one copy, restored read-only from the remaining copy |
| `cargo clippy --all-targets --no-deps --locked -- -D warnings` | Passed for Vault |
| `cargo fmt --package cyber-vault --check` | Passed |

[Commands, exit codes and timings](checks.json), [full tests](tests.log),
[core tests](core-tests.log), [demonstration output](example.log),
[Clippy](clippy.log), [format](format.log).

The example's single run measured creation **670 ms** (includes password KDF),
credential insertion **3 ms**, local replication **26 ms**, recovery-factor
restore **12 ms**, and **1,900 bytes** of retained ciphertext packet history.
These are one synthetic credential on one macOS arm64 machine with temporary
local stores. They exclude network latency, independent hardware failure,
filesystem/database overhead in the byte count and repeated benchmark sampling.
They are a runnable drill, not throughput or durability performance claims.

The three existing vendored Fjall warnings remain in dependency build output.
Vault's `--no-deps -D warnings` check passes; this does not certify sibling code.

## Source and build provenance

The [source-state manifest](source-state.json) records the Rust toolchain, local
dependency package paths, repository heads, dirty-state counts and Rust/Cargo
source digests. This run depends on compatible local sibling changes, including
Cybergraph's application storage and Mudra's current neuron subject APIs.
Those unrelated changes were neither edited nor published by this Vault change.
`Cargo.lock` fixes registry resolution; it does not freeze sibling path sources.
A clean-checkout CI build requires publishing/pinning compatible dependency
revisions. The repository's `0.1.0` package version is not a production release.

Only synthetic fixtures and temporary stores were used. No real user seed,
password, token, enrollment or recovery material was opened or imported.

## Limits and next gates

- **Isolation and Ward:** this is a library inside a trusted process, with a
  guarded authorization port. Tests/example use synthetic Ward adapters. There
  is no shipped authenticated IPC, native isolation, protected input UI or
  production revocation integration. A hostile host can bypass a library boundary.
- **Replica evidence:** readback proves the selected local copies were present
  at verification time. Labels do not prove independent hardware; evidence does
  not promise continuing retention or availability. No authenticated network
  receipt, traffic privacy, provider lease or transport adapter is implemented.
- **Freshness and writer authority:** the host retains the exact recovery
  anchor. The library cannot discover a globally freshest checkpoint or fence a
  writer on another machine. Recovery-factor opening is deliberately read-only;
  there is no writer-promotion path. Password opening is for resuming the existing
  writer, not independently authorizing a replacement.
- **Uncertain creation:** uncertain later mutations retain a candidate anchor
  and freeze until reconciliation. An uncertain genesis still requires a host
  reconciliation flow; `create` must not be reported successful in that case.
- **Scope:** signing, foreign account binding, passkeys, hardware custody,
  key/factor rotation, production service delivery adapters and migration from
  Neuron/Mudra's existing public seed APIs remain work. `derive_neuron` only
  derives public credentials; it does not prove external account control.
- **Storage and memory:** full snapshots are bounded to 128 entries and 4096
  revisions; there is no compaction or forensic deletion. Old ciphertexts retain
  previous secret versions. Third-party derivation internals and operating-system
  memory behavior are not qualified by `Zeroizing` wrappers. Crash fault
  injection/reopen tests are not physical power-cut or cross-platform tests.

These results exercise parts of the [conformance matrix](../../specs/conformance.md).
They do not close its native deployment, network synchronization, handover,
fault-platform or migration gates. The [roadmap](../../roadmap/README.md) orders
those remaining integration steps.
