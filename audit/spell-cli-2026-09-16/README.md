# Spell terminology and local CLI — 2026-09-16

The Vault/Mudra/Cyb custody path now uses `spell` for root recovery words and
derived material. Mudra owns `spell::{derive, signing_key, cosmos_key, generate}`;
Vault owns `SecretInput::spell` and `SecretKind::Spell`. Wire tag **7**, the
64-byte BIP-39 result, key derivation, addresses and neuron bytes are unchanged.
Existing records need no rewrite. Cyb's legacy filename/kind readers remain;
new installations use `~/cyb/spell`. Historical audit evidence and third-party
BIP-39 API names retain their original spelling. PRNG/network/bootstrap seeds
are different concepts. Unrelated wallet implementations are outside this change.

## Implemented host

`target/release/vault` provides initialization, typed import, paged catalog,
versioned removal, local replica registration/copy verification, terminal reveal,
OTP/recovery-code use, public neuron derivation, checkpoint export and read-only
recovery. [Contract](../../specs/cli.md) · [Guide](../../docs/cli.md).

The CLI keeps ciphertext in Cybergraph/BBG. An owner-only sidecar retains the
expected anchor and exact candidate before append; it contains no entry payloads
or keys. An exclusive OS lock and successful unlock authenticate the local
operator. The private Ward adapter checks the exact actor, vault, request and
command, and holds that authority through delivery. Spells/domain roots cannot
be revealed. Imported tokens await a destination-specific application adapter.

## Executed checks

All inputs were synthetic. No real user custody file was inspected or imported.

| Check | Evidence |
|---|---|
| Complete release suite | 39 tests passed, including the existing 4,352-live-entry / 4,356-revision recovery scenario |
| Final CLI regression suite | 8 tests passed after adding initialization protection; 40 distinct Rust tests covered across the full and final runs |
| Adapter-free library | 7 tests passed |
| Actual pseudo-terminal | Hidden input did not echo; password and codes went only to the terminal, while redirected stdout/stderr contained no secret values |
| HOTP / one-time codes | RFC 4226 first/second values; exact request retry retained the first result; recovery-code exhaustion rejected |
| Process recovery | Imported spell survived restarts; derived public key/address matched Mudra; after primary deletion a retained checkpoint restored metadata from a replica in read-only mode |
| Host commit crash points | Reopened a committed genesis and mutation before host finalization; only the previously retained candidate was adopted; an uncommitted candidate retained the prior anchor |
| Denials | Wrong unlock, changed retry input, stale checkpoint, insecure file permissions, another host lock owner, another actor/request/operation, root reveal, and init over data with missing metadata rejected |
| Static/build | Package format, Clippy with warnings denied for owned code, and release binary build passed |
| Mudra consumers | 19 library tests and 2 independent Cosmos-vector tests passed; minimal-feature library passed |
| Cyb consumers | CLI/GUI compilation, 3 focused spelling/legacy-format tests and the required three-body fleet passed (21 checks) |

The unoptimized full run was stopped during the long capacity scenario and
replaced by the complete release run; it is not counted as a pass. Existing
vendored Fjall warnings remain dependency warnings. Compatible sibling working
trees were used; concurrent native-neuron/node work was excluded from the
terminology commits. The lockfile reflects their current transitive package graph.

[Full release results](release-tests.log) · [Final CLI results](cli-tests.log) ·
[Minimal build](core-tests.log) · [Terminal exercise](terminal-tests.log) ·
[Clippy](clippy.log) · [Cyb fleet](cyb-fleet.log).

## Qualification boundary

This is a macOS/Linux local operator CLI. OS account/process trust, declared
replica failure domains and independently retained checkpoints are explicit
assumptions. Local labels/readback do not prove separate hardware or remote
retention. Rollback of both host state and database needs an external checkpoint.
Recovery verifies and lists the selected revision; activating a replacement
writer requires the later fencing/handover profile. Failed initialization may
leave reserved host/factor artifacts; these are never silently deleted or replaced.

Native custody isolation, general Ward integration, authenticated network sync,
portable discovery, key rotation and Cyb's migration into this custody service
remain distinct work. Renaming Cyb's existing interfaces does not migrate its
legacy secret store. No production-release or hardware-isolation claim follows.

Companion changes: [Mudra #2](https://github.com/cyberia-to/mudra/pull/2),
[Cyb #1391](https://github.com/cyberia-to/cyb/pull/1391),
[soft3 #3](https://github.com/cyberia-to/soft3/pull/3).
