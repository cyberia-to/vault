# Local Vault CLI

The `vault` binary is a trusted local operator host for the custody library.
It owns one Cybergraph/BBG store; its command-scoped Ward adapter grants the
authenticated local owner exactly the requested action while holding an
exclusive host lock. OS account isolation and the unlocked process are part
of this profile's trust boundary. Agents and remote callers require their own
Ward integration.

## Commands

`--home PATH` selects a private host directory (default `~/.cyber/vault`).

| Command | Contract |
|---|---|
| `init --recovery-file PATH` | Create a store and a new, exclusive 0600 recovery-factor file; confirm the unlock password |
| `status` | Report local anchor and pending commit metadata without unlocking |
| `list [--after ID] [--limit N]` | Unlock and return one catalog page; no total catalog limit |
| `add KIND --label LABEL --scope SCOPE` | Import a typed secret or generate a domain root; return its opaque ID |
| `remove ID --version N` | Delete the exact entry version |
| `replica-add --path PATH --failure-domain NAME` | Register a local ciphertext destination |
| `sync` | Copy and read back the complete encrypted history to registered replicas |
| `show ID` | Reveal a revealable password/PIN to the controlling terminal |
| `otp ID` / `recovery-code ID` | Reserve use durably, replicate, then deliver to the controlling terminal |
| `derive-neuron ID [--path PATH / --domain DOMAIN]` | Derive inside custody and emit public credentials after replication |
| `checkpoint --out PATH` | Export the authenticated revision and public host context; never a secret |
| `recover --database PATH --checkpoint PATH --recovery-file PATH` | Authenticate exact retained history and list a page in read-only recovery mode |

`spell` is the canonical root-word kind. A spell import requests words and
the optional BIP-39 passphrase separately. Passwords, PINs, tokens, OTP keys,
recovery codes, spells and unlock passwords never enter arguments or environment
variables. Default input uses hidden terminal prompts. Explicit `--secrets-stdin`
reads one line per prompt from a pipe for host automation; redirected terminal
input is otherwise not accepted. OTP enrollment accepts unpadded base32.
Protected output goes only to the controlling terminal, never redirected stdout;
spells and domain roots have no reveal/export command. Ordinary results are JSON.

## Durability and retries

The host durably retains its expected revision independently of the graph DB.
Before append it retains the exact request, prior anchor and ciphertext-derived
candidate anchor. Restart reconciliation accepts only that retained candidate or
the unchanged prior anchor and authenticates the complete chain before advancing
the host checkpoint. It never adopts an arbitrary database head. A process crash
after DB commit and before metadata update therefore needs no rollback bypass.

Host files are owner-only, atomically replaced and fsynced. This guards against
database-only rollback; rollback of the entire host still needs an independently
retained checkpoint. Recovery requires an explicit checkpoint and stays read-only.
The recovery factor does not reconstruct imported secrets without ciphertext.

`--request HEX` retains an operation's retry identity. Mutating invocations report
their request ID before committing; `add --id HEX` also allows an exact input retry.
HOTP and recovery-code retries must reuse the original request and command. A new
request consumes a new value. Errors never contain secret inputs.

Release needs two readback-verified copies with distinct replica IDs and declared
failure-domain names. Paths must be distinct and must not overlap the primary or
another replica. Names are operator assertions, not proof of independent hardware;
this command implements local copies, not network authentication or consensus.
