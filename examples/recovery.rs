//! Synthetic demonstration only: this host adapter is not a production Ward.
use std::time::Instant;
use vault::*;
use zeroize::Zeroizing;

struct DemoWard(Context);
impl Ward for DemoWard {
    fn with_authorization<T>(
        &self,
        intent: &Intent,
        action: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        if intent.context != self.0 {
            return Err(Error::Denied);
        }
        action(59)
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let context = Context {
        actor: ActorId([1; 32]),
        policy: PolicyRef([2; 32]),
    };
    let ward = DemoWard(context);
    let id = VaultId::random()?;
    let recovery = Zeroizing::new([7u8; 32]); // Synthetic, public test material.
    let created = Instant::now();
    let mut vault = Vault::create(
        GraphStore::open(directory.path().join("primary"))?,
        id,
        RequestId::random()?,
        context,
        b"synthetic-demo-unlock-only",
        &recovery,
        &ward,
    )?;
    let create_ms = created.elapsed().as_millis();
    let replicas = vec![
        Replica {
            id: [3; 32],
            failure_domain: "demo-a".into(),
            store: GraphStore::open(directory.path().join("replica-a"))?,
        },
        Replica {
            id: [4; 32],
            failure_domain: "demo-b".into(),
            store: GraphStore::open(directory.path().join("replica-b"))?,
        },
    ];
    let password = SecretRef::random()?;
    let committed = Instant::now();
    vault.put(
        context,
        RequestId::random()?,
        Entry::new(
            password,
            "Synthetic password".into(),
            "https://example.invalid".into(),
            context.policy,
            true,
            SecretInput::password(Zeroizing::new(b"synthetic-secret-value".to_vec()))?,
        )?,
        None,
        &ward,
    )?;
    let put_ms = committed.elapsed().as_millis();
    let pending = vault.prepare_use(
        context,
        RequestId::random()?,
        Operation::Reveal {
            secret: password,
            surface: "demo-protected-output".into(),
        },
        &ward,
    )?;
    let replicated = Instant::now();
    let copies = vault.replicate(&replicas)?;
    let replicate_ms = replicated.elapsed().as_millis();
    vault.release(context, &pending, &copies, &ward, |output| match output {
        Output::Secret(value) if value.as_slice() == b"synthetic-secret-value" => Ok(()),
        _ => Err(Error::Corrupt),
    })?;
    let anchor = vault.revision();
    let ciphertext_bytes: usize = vault
        .store()
        .history(id)?
        .into_iter()
        .map(|r| vault.store().read(r).map(|v| v.bytes.len()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum();
    drop(vault);
    drop(replicas);
    std::fs::remove_dir_all(directory.path().join("primary"))?;
    std::fs::remove_dir_all(directory.path().join("replica-a"))?;
    let recovered = Instant::now();
    let restored = Vault::recover(
        GraphStore::open(directory.path().join("replica-b"))?,
        id,
        anchor,
        &recovery,
    )?;
    let restore_ms = recovered.elapsed().as_millis();
    assert_eq!(restored.mode(), AccessMode::RecoveryReadOnly);
    assert_eq!(restored.inspect(context, &ward)?.len(), 1);
    println!(
        "Verified: local commit, two ciphertext copies, protected use, recovery after loss of primary and one copy."
    );
    println!(
        "Restored revision {}; read-only. All stores were synthetic and on one test machine.",
        anchor.index
    );
    println!(
        "create_ms={create_ms} put_ms={put_ms} replicate_ms={replicate_ms} restore_ms={restore_ms} ciphertext_history_bytes={ciphertext_bytes}"
    );
    Ok(())
}
