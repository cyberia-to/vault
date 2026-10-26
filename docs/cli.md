# Use the local Vault CLI

Build with `cargo build --release --bin vault --locked` and run
`./target/release/vault` to show the same help as `--help`. The default home is `~/.cyber/vault`;
`--home PATH` selects another owner-only directory. This local host currently
supports macOS and Linux.

The terminal help follows Mudra/Cyb's rainbow wordmark and aligned command groups.
Use `vault <command> --help` for individual options. Piped help is plain text;
`NO_COLOR=1` disables color and `TERM=dumb` uses the compact presentation.
Command results remain JSON for scripts.

## Create and store

`vault init --recovery-file PATH` asks for a new unlock password twice and
creates a 0600 recovery-factor file at the explicit destination. Keep that file
outside the host directory and on separate protected storage. It can decrypt
your retained ciphertext; it cannot recreate lost records.

`vault add KIND --label LABEL --scope SCOPE` imports `password`, `pin`, `token`,
`spell`, `totp`, `hotp` or `recovery-codes`. `domain-root` generates a random root
inside custody. Each command asks for the unlock password first. `spell` then
asks for the words and optional BIP-39 passphrase. OTP enrollment asks for a
base32 key; `--algorithm sha256`, `--digits 8`, `--period` and `--counter` select
its profile. Recovery codes are entered one per hidden prompt, ending with an
empty line. Only passwords and PINs may opt into `--revealable`.

Results are JSON and contain opaque entry IDs. `vault list --limit 100` reads
one page. Continue with `--after ID` using the last returned ID until the page
is empty. This does not limit total entries or revision history.

## Copy and use

Register two destinations with `vault replica-add --path PATH --failure-domain NAME`.
Use distinct disks/devices and names. `vault sync` writes ciphertext through
Cybergraph/BBG and reads back the entire required history from each destination.
This is local filesystem replication. Remote authenticated sync remains a
separate integration.

- `vault show ID`: display a revealable password/PIN on the controlling terminal.
- `vault otp ID`: display the current TOTP or durably consume a HOTP counter.
- `vault recovery-code ID`: durably consume one code.
- `vault derive-neuron ID --hrp bostrom`: return public credentials derived from a spell.
- `vault derive-neuron ID --domain example.test --hrp bostrom`: use a domain root.
- `vault sign ID --subject NEURON_HEX --statement COMMITMENT_HEX`: sign a native
  action with the selected spell key; add `--domain example.test` for a domain root.
  The result contains public NSIG1 evidence. Keep `--request HEX` for exact retries.
- `vault remove ID --version N`: delete the exact version shown by `list`.

Protected output is delivered after reservation and two verified copies. Secret
output goes to the controlling terminal even if stdout is redirected. Control
characters, non-ASCII bytes and backslashes are rendered as `\xNN` byte escapes.
Root spells, domain roots and tokens have no generic reveal route. Destination-bound
token delivery belongs to an application host adapter.

Every mutating/use command reports a public request ID to stderr before committing.
After an interrupted operation, repeat the same command with `--request HEX`.
For an `add` retry also use the reported `--id HEX` and identical entry inputs.
HOTP/recovery-code retries reuse the reserved result; a new request consumes a new
value. TOTP retries remain valid only during the originally authorized time window.

## Recover

After the latest use and sync, export `vault checkpoint --out PATH` and retain it
independently. Export paths are never overwritten. Recovery checks the exact
retained revision:

```sh
vault recover --database /Volumes/backup-b/vault \
  --checkpoint /path/to/checkpoint.json \
  --recovery-file /path/to/recovery.factor
```

This verifies recovery and lists metadata in `RecoveryReadOnly` mode. It does
not activate a replacement writer or release secrets. A checkpoint from an
older revision does not authorize adoption of a newer database head. `status`
reports local metadata without password authentication; `list` authenticates
the encrypted chain. Neither local metadata nor a database can establish
freshness after both were rolled back together.

## Host automation

Use `--secrets-stdin` only with a trusted pipe that supplies one newline-terminated
line per prompt, in prompt order. Do not place secrets in command arguments,
environment variables, shell history or logs. Terminal input is hidden by default;
the explicit pipe mode rejects a terminal whose input would echo. Secret
delivery still requires a controlling terminal. Public derived credentials and
authorized metadata may be read as JSON on stdout.
