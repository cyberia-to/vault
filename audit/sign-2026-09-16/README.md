# Native signing and Neuron custody — 2026-09-16

Vault now exposes `sign` and the `sign` CLI command. The exact key reference,
subject and statement enter the existing Ward/receipt protocol. Mudra produces
the existing NSIG1 bytes; Vault releases evidence only after committing the
encrypted result, verifying two replica copies and checking current permission.

The `local-host` feature factors the existing CLI host into shared library code.
`local::Signer` uses the same owner-only paths, exclusive lock, retained candidate
journal and authenticated restart reconciliation, and retains the derived public
subject per key reference and root version so that reopening commits nothing. Neuron's `LocalVault` adapter
uses that signer through `SigningVault::sign`; its current action grant covers
the entire call. The CLI selects custody with `--vault-home` and `--vault-root`,
with explicit spell-path or domain derivation. The old raw-key path is explicit
and mutually exclusive; failures never select it as a fallback.

## Evidence

All inputs were synthetic; no real user custody was opened or migrated.

**This directory retains no run log.** The runs below were executed on the
author's desk against sibling working trees; nothing in this tree confirms them
independently. Neither does the build server's gate on this commit: it is red,
because a clean checkout resolves a published `cybergraph` 0.1.1 that has no
`local-storage` feature. **No independently checkable evidence of these runs
exists yet.** It is still owed, as retained logs for the signing suite or as a
green gate once the compatible sibling revisions are published.

The logs retained under [the CLI qualification](../spell-cli-2026-09-16/README.md)
predate the signing work: `release-tests.log` totals 39 passing tests, lists
four tests in `tests/cli.rs` where the suite now has five, and contains no
`tests/sign.rs` section.

What the tree itself shows: 46 `#[test]` functions across the library and the
integration suites, of which `tests/sign.rs` holds four and `tests/cli.rs` five.

| Check | Reported result, not retained here |
|---|---|
| Vault full release suite | 45 tests passed, including the existing 4,352-entry/history recovery case |
| Added canonical signing-codec test | Passed |
| Vault minimal features | 8 tests passed |
| Vault Clippy, all targets, owned code | Passed with `-D warnings` |
| Neuron full release workspace suite | 47 tests passed |
| Neuron CLI/node Clippy, all targets, owned code | Passed with `-D warnings` |
| Mudra library / independent Cosmos vectors | 19 + 2 tests passed |
| Mudra minimal-feature library | 16 tests passed |
| Release binaries and pseudo-terminal exercise | Built; hidden input, terminal-only output, HOTP retries and root-reveal denial passed |

Signing tests compare both spell/Cosmos and domain-root outputs with an
independently assembled legacy ADR-036 envelope. They cover HRP independence,
wrong subject/type/profile, denied preparation, missing/stale copies, revoked
release, changed root version, read-only restore, exact retry after reopening,
conflicting request reuse, uncertain append reconciliation and malformed codecs.

The process tests exercise the shared CLI/library lock, identical persisted
receipts and a complete Neuron activation/install/execute/retry across processes
using only an encrypted Vault. Neuron's tests verify publication signatures and
revocation before the next publication. Existing host tests also run from their
new shared module and retain coverage of the commit-before-checkpoint crash gap.

## Scope and source state

This is the trusted local-operator profile. It does not supply isolated custody,
authenticated remote Ward decisions, live private network synchronization or
replacement-writer fencing. Configured replica labels do not attest independent
hardware. Reopening and copy verification still walk retained history in pages;
this change makes no signing-throughput or production qualification claim.
Third-party derivation temporaries retain the memory-hygiene limitations already
declared by the local custody profile.

Tests use the compatible sibling working trees. Neuron already contained a large
uncommitted cell-to-neuron convergence before this change. The integration is
applied and tested there. Its isolated delta belongs to the companion Neuron
pull request and is no longer vendored here: this repository does not carry
another repository's working-tree diff. That delta must land with the
convergence prerequisite; it is not a standalone patch against Neuron's old
committed cell runtime. The unrelated working-tree changes remain preserved.

The Mudra change exposes the existing native envelope with canonical `sign` and
a compatibility alias. Its unrelated identity-crate/dependency/proving changes
are excluded from the signing commit.
