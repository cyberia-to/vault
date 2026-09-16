use super::{
    Result,
    args::{Algorithm, Args, Command, Kind},
    host::{Host, JournaledStore, ReplicaConfig, State},
    io,
    owner::{Grant, Owner},
};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use vault::{
    Context, Derivation, Entry, GraphStore, NeuronKeyRef, Operation, OtpAlgorithm, Output, Replica,
    RequestId, Revision, SecretInput, SecretRef, Vault, VaultId,
};
use zeroize::Zeroizing;

pub fn run(args: Args) -> Result<()> {
    if let Command::Recover {
        database,
        checkpoint,
        recovery_file,
        after,
        limit,
    } = &args.command
    {
        return recover(database, checkpoint, recovery_file, after, *limit);
    }
    let home = match &args.home {
        Some(path) => path.clone(),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset; pass --home")?)
            .join(".cyber/vault"),
    };
    let request = args
        .request
        .as_deref()
        .map(io::array)
        .transpose()?
        .map(RequestId)
        .map_or_else(RequestId::random, Ok)?;
    if let Command::Init { recovery_file } = &args.command {
        return init(&home, recovery_file, args.secrets_stdin, request);
    }
    let host = Host::open(&home, false)?;
    let state = host.state()?;
    if matches!(args.command, Command::Status) {
        return print(
            json!({"vault": hex::encode(state.vault), "anchor": state.anchor.map(|r| revision(r.into())),
            "pending_commit": state.pending.as_ref().map(|p| revision(p.candidate.into())),
            "replicas": state.replicas.len(), "authenticated": false}),
        );
    }
    let password = io::secret("Unlock password: ", args.secrets_stdin)?;
    let mut vault = Vault::open(
        host.store.clone(),
        VaultId(state.vault),
        host.opening_anchor()?,
        password.as_bytes(),
    )?;
    drop(password);
    host.settle(vault.revision())?;
    let context = state.context();
    let owner = |grant| Owner {
        vault: vault.id(),
        context,
        request,
        grant,
    };
    match args.command {
        Command::List { after, limit } => {
            let entries = vault.inspect_page(
                context,
                secret_ref(after.as_deref())?,
                limit,
                &owner(Grant::Inspect),
            )?;
            print_entries(vault.revision(), entries, "Active")
        }
        Command::Add {
            kind,
            label,
            scope,
            id,
            revealable,
            digits,
            period,
            counter,
            algorithm,
        } => {
            let id = secret_ref(id.as_deref())?.map_or_else(SecretRef::random, Ok)?;
            let input = input(kind, algorithm, digits, period, counter, args.secrets_stdin)?;
            let entry = Entry::new(id, label, scope, context.policy, revealable, input)?;
            let ward = owner(Grant::Put(entry.info().clone()));
            report_request(request, Some(id));
            vault.put(context, request, entry, None, &ward)?;
            host.settle(vault.revision())?;
            print(
                json!({"id": hex::encode(id.0), "request": hex::encode(request.0), "revision": revision(vault.revision())}),
            )
        }
        Command::Remove { id, version } => {
            let id = SecretRef(io::array(&id)?);
            let ward = owner(Grant::Delete(id, version));
            report_request(request, Some(id));
            vault.delete(context, request, id, version, &ward)?;
            host.settle(vault.revision())?;
            print(json!({"removed": hex::encode(id.0), "revision": revision(vault.revision())}))
        }
        Command::ReplicaAdd {
            path,
            failure_domain,
        } => {
            add_replica(&host, &path, failure_domain)?;
            print(json!({"replicas": host.state()?.replicas.len()}))
        }
        Command::Sync => {
            let replicas = replicas(&host)?;
            let evidence = vault.replicate(&replicas)?;
            print(
                json!({"copies": evidence.copies(), "revision": revision(evidence.revision()), "evidence": "local-readback"}),
            )
        }
        Command::Checkpoint { out } => {
            io::new_file(
                &out,
                &serde_json::to_vec_pretty(&host.state()?.checkpoint()?)?,
            )?;
            print(json!({"revision": revision(vault.revision()), "checkpoint": out}))
        }
        Command::Show { id } => use_secret(
            &host,
            &mut vault,
            context,
            request,
            Operation::Reveal {
                secret: SecretRef(io::array(&id)?),
                surface: "local-owner:/dev/tty".into(),
            },
        ),
        Command::Otp { id } => use_secret(
            &host,
            &mut vault,
            context,
            request,
            Operation::Otp {
                secret: SecretRef(io::array(&id)?),
            },
        ),
        Command::RecoveryCode { id } => use_secret(
            &host,
            &mut vault,
            context,
            request,
            Operation::RecoveryCode {
                secret: SecretRef(io::array(&id)?),
            },
        ),
        Command::DeriveNeuron {
            id,
            path,
            domain,
            hrp,
        } => {
            let derivation = match domain {
                Some(domain) => Derivation::Domain { domain, hrp },
                None => Derivation::Cosmos {
                    path: path.unwrap_or_else(|| mudra::spell::COSMOS_PATH.into()),
                    hrp,
                },
            };
            use_secret(
                &host,
                &mut vault,
                context,
                request,
                Operation::DeriveNeuron(NeuronKeyRef {
                    root: SecretRef(io::array(&id)?),
                    derivation,
                }),
            )
        }
        Command::Init { .. } | Command::Status | Command::Recover { .. } => unreachable!(),
    }
}

fn init(home: &Path, recovery_file: &Path, piped: bool, request: RequestId) -> Result<()> {
    if recovery_file.try_exists()? {
        return Err("recovery file already exists; it will not be overwritten".into());
    }
    let password = io::secret("New unlock password: ", piped)?;
    let confirm = io::secret("Repeat unlock password: ", piped)?;
    if !(12..=1024).contains(&password.len()) || *password != *confirm {
        return Err("unlock passwords must match and contain 12–1024 bytes".into());
    }
    drop(confirm);
    io::private_dir(home)?;
    let home = home.canonicalize()?;
    let parent = recovery_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    if parent.starts_with(&home) {
        return Err("recovery file must be outside the host directory".into());
    }
    let mut recovery = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(recovery.as_mut()).map_err(|_| "entropy unavailable")?;
    let host = Host::open(&home, true)?;
    io::new_file(recovery_file, recovery.as_ref())?;
    let state = host.state()?;
    let ward = Owner {
        vault: VaultId(state.vault),
        context: state.context(),
        request,
        grant: Grant::Create,
    };
    report_request(request, None);
    let vault = Vault::create(
        host.store.clone(),
        ward.vault,
        request,
        ward.context,
        password.as_bytes(),
        &recovery,
        &ward,
    )?;
    host.settle(vault.revision())?;
    print(
        json!({"vault": hex::encode(state.vault), "revision": revision(vault.revision()), "home": host.directory, "recovery_file": recovery_file}),
    )
}

fn input(
    kind: Kind,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    counter: u64,
    piped: bool,
) -> Result<SecretInput> {
    let algorithm = match algorithm {
        Algorithm::Sha1 => OtpAlgorithm::Sha1,
        Algorithm::Sha256 => OtpAlgorithm::Sha256,
    };
    let bytes = |prompt| -> Result<_> {
        Ok(Zeroizing::new(
            io::secret(prompt, piped)?.as_bytes().to_vec(),
        ))
    };
    Ok(match kind {
        Kind::Password => SecretInput::password(bytes("Password: ")?)?,
        Kind::Pin => SecretInput::pin(bytes("PIN: ")?)?,
        Kind::Token => SecretInput::token(bytes("Service token: ")?)?,
        Kind::Spell => {
            let words = io::secret("Spell words: ", piped)?;
            let passphrase = io::secret("BIP-39 passphrase (empty if none): ", piped)?;
            SecretInput::spell(&words, &passphrase)?
        }
        Kind::DomainRoot => SecretInput::generate_domain_root()?,
        Kind::Totp | Kind::Hotp => {
            let value = io::secret("OTP enrollment key (base32): ", piped)?;
            let normalized =
                Zeroizing::new(value.trim().trim_end_matches('=').to_ascii_uppercase());
            let key = Zeroizing::new(
                data_encoding::BASE32_NOPAD
                    .decode(normalized.as_bytes())
                    .map_err(|_| "invalid OTP enrollment key")?,
            );
            match kind {
                Kind::Totp => SecretInput::totp(key, algorithm, digits, period)?,
                _ => SecretInput::hotp(key, algorithm, digits, counter)?,
            }
        }
        Kind::RecoveryCodes => {
            let mut codes = Vec::new();
            loop {
                let value = bytes("Recovery code (empty line ends the set): ")?;
                if value.is_empty() {
                    break;
                }
                codes.push(value);
                if codes.len() > 64 {
                    return Err("one recovery-code enrollment supports up to 64 codes".into());
                }
            }
            SecretInput::recovery_codes(codes)?
        }
    })
}

fn add_replica(host: &Host, path: &Path, failure_domain: String) -> Result<()> {
    let mut state = host.state()?;
    if state.replicas.len() >= 8
        || failure_domain.is_empty()
        || failure_domain.len() > 256
        || state
            .replicas
            .iter()
            .any(|r| r.failure_domain == failure_domain)
    {
        return Err(
            "replica configuration requires distinct failure domains (2–8 copies per operation)"
                .into(),
        );
    }
    io::private_dir(path)?;
    let path = path.canonicalize()?;
    let overlaps = |other: &Path| path.starts_with(other) || other.starts_with(&path);
    if overlaps(&host.directory) || state.replicas.iter().any(|r| overlaps(&r.path)) {
        return Err("replica paths must not overlap the host or each other".into());
    }
    state.replicas.push(ReplicaConfig {
        id: RequestId::random()?.0,
        path,
        failure_domain,
    });
    host.save(state)
}

fn replicas(host: &Host) -> Result<Vec<Replica<GraphStore>>> {
    let state = host.state()?;
    if state.replicas.len() < 2 {
        return Err(vault::Error::ReplicationRequired.into());
    }
    state
        .replicas
        .into_iter()
        .map(|r| {
            io::check_private(&r.path, true)?;
            if r.path.canonicalize()? != r.path {
                return Err("replica path changed".into());
            }
            Ok(Replica {
                id: r.id,
                failure_domain: r.failure_domain,
                store: GraphStore::open(r.path)?,
            })
        })
        .collect()
}

fn use_secret(
    host: &Host,
    vault: &mut Vault<Arc<JournaledStore>>,
    context: Context,
    request: RequestId,
    operation: Operation,
) -> Result<()> {
    // Validate destinations before consuming a one-time value.
    let public = matches!(operation, Operation::DeriveNeuron(_));
    let mut terminal = if public { None } else { Some(io::tty()?) };
    let replicas = replicas(host)?;
    let ward = Owner {
        vault: vault.id(),
        context,
        request,
        grant: Grant::Use(operation.clone()),
    };
    report_request(request, Some(operation.secret()));
    let pending = vault.prepare_use(context, request, operation, &ward)?;
    host.settle(vault.revision())?;
    let evidence = vault.replicate(&replicas)?;
    let result = vault.release(context, &pending, &evidence, &ward, |output| {
        match output {
            Output::Secret(bytes) => {
                let terminal = terminal.as_mut().ok_or(vault::Error::Denied)?;
                // Escaping avoids terminal control-sequence execution while preserving content.
                for &byte in bytes.iter() {
                    if (0x20..=0x7e).contains(&byte) && byte != b'\\' {
                        terminal.write_all(&[byte]).map_err(|_| vault::Error::Storage)?;
                    } else {
                        write!(terminal, "\\x{byte:02x}").map_err(|_| vault::Error::Storage)?;
                    }
                }
                writeln!(terminal).and_then(|_| terminal.flush()).map_err(|_| vault::Error::Storage)?;
                Ok(json!({"delivered_to": "controlling-terminal"}))
            }
            Output::Neuron { subject, public_key, address, .. } if public =>
                Ok(json!({"neuron": hex::encode(subject), "public_key": hex::encode(public_key), "address": address})),
            _ => Err(vault::Error::Denied),
        }
    })?;
    print(
        json!({"request": hex::encode(request.0), "revision": revision(vault.revision()), "result": result}),
    )
}

fn recover(
    database: &Path,
    checkpoint: &Path,
    recovery_file: &Path,
    after: &Option<String>,
    limit: usize,
) -> Result<()> {
    let state = State::read(checkpoint)?.checkpoint()?;
    let bytes = io::read_private(recovery_file, 32)?;
    let factor = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "invalid recovery factor file")?,
    );
    io::check_private(database, true)?;
    let graph = GraphStore::open(database)?;
    let anchor = state.anchor.ok_or("missing checkpoint revision")?.into();
    let vault = Vault::recover(graph, VaultId(state.vault), anchor, &factor)?;
    let context = state.context();
    let ward = Owner {
        vault: vault.id(),
        context,
        request: RequestId([0; 32]),
        grant: Grant::Inspect,
    };
    let entries = vault.inspect_page(context, secret_ref(after.as_deref())?, limit, &ward)?;
    print_entries(anchor, entries, "RecoveryReadOnly")
}

fn secret_ref(value: Option<&str>) -> Result<Option<SecretRef>> {
    Ok(value.map(io::array).transpose()?.map(SecretRef))
}
fn report_request(request: RequestId, id: Option<SecretRef>) {
    eprintln!(
        "{}",
        json!({"request": hex::encode(request.0), "id": id.map(|id| hex::encode(id.0))})
    );
}
fn revision(r: Revision) -> Value {
    json!({"index": r.index, "commit": hex::encode(r.commit)})
}
fn print(value: Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    writeln!(out)?;
    Ok(())
}
fn print_entries(anchor: Revision, entries: Vec<vault::EntryInfo>, mode: &str) -> Result<()> {
    let after = entries.last().map(|e| hex::encode(e.id.0));
    let entries: Vec<_> = entries
        .into_iter()
        .map(|e| {
            json!({
                "id": hex::encode(e.id.0), "kind": format!("{:?}", e.kind), "label": e.label,
                "scope": e.scope, "version": e.version, "revealable": e.revealable,
            })
        })
        .collect();
    print(json!({"mode": mode, "revision": revision(anchor), "entries": entries, "after": after}))
}
