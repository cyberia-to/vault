#![cfg(feature = "graph-store")]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use vault::*;
use zeroize::Zeroizing;

#[test]
fn graph_views_share_the_existing_database_owner_and_keep_namespaces_separate() {
    use cybergraph::application::{Backend, Database};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared");
    let db = Database::open(&path, Backend::Ssd).unwrap();
    let ward = TestWard::new();
    let mut first = Vault::create(
        GraphStore::from_database(db.clone()),
        VaultId::random().unwrap(),
        request(),
        context(),
        PASSWORD,
        &RECOVERY,
        &ward,
    )
    .unwrap();
    let second = Vault::create(
        GraphStore::from_database(db.clone()),
        VaultId::random().unwrap(),
        request(),
        context(),
        PASSWORD,
        &RECOVERY,
        &ward,
    )
    .unwrap();
    first
        .put(
            context(),
            request(),
            entry(SecretRef::random().unwrap(), password(b"first-only"), true),
            None,
            &ward,
        )
        .unwrap();
    assert_eq!(first.inspect(context(), &ward).unwrap().len(), 1);
    assert!(second.inspect(context(), &ward).unwrap().is_empty());
    assert!(
        GraphStore::open(&path).is_err(),
        "must not open a competing physical writer"
    );
}

#[test]
fn independent_factor_restores_after_loss_of_primary_and_one_replica() {
    let mut f = Fixture::new();
    f.put(password(b"external-password"), true);
    f.put(
        SecretInput::pin(Zeroizing::new(b"1234".to_vec())).unwrap(),
        true,
    );
    f.put(
        SecretInput::token(Zeroizing::new(b"synthetic-api-token".to_vec())).unwrap(),
        false,
    );
    f.put(
        SecretInput::hotp(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            4,
        )
        .unwrap(),
        false,
    );
    f.put(
        SecretInput::totp(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap(),
        false,
    );
    f.put(
        SecretInput::recovery_codes(vec![Zeroizing::new(b"backup-code".to_vec())]).unwrap(),
        false,
    );
    f.put(SecretInput::generate_domain_root().unwrap(), false);
    f.put(
        SecretInput::mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap(),
        false,
    );
    let copies = f.vault.replicate(&f.replicas).unwrap();
    let id = f.vault.id();
    let anchor = copies.revision();
    let expected = f.vault.inspect(context(), &f.ward).unwrap();
    drop(f.vault);
    drop(f.store);
    drop(f.replicas);
    std::fs::remove_dir_all(f.directory.path().join("primary")).unwrap();
    std::fs::remove_dir_all(f.directory.path().join("a")).unwrap();
    let mut restored = Vault::recover(
        GraphStore::open(f.directory.path().join("b")).unwrap(),
        id,
        anchor,
        &RECOVERY,
    )
    .unwrap();
    assert_eq!(restored.mode(), AccessMode::RecoveryReadOnly);
    assert_eq!(restored.inspect(context(), &f.ward).unwrap(), expected);
    assert_eq!(
        restored.put(
            context(),
            request(),
            entry(SecretRef::random().unwrap(), password(b"new"), true),
            None,
            &f.ward
        ),
        Err(Error::ReadOnly)
    );
}

#[test]
fn wrong_factors_and_wrong_vault_do_not_unlock() {
    let f = Fixture::new();
    let id = f.vault.id();
    let head = f.vault.revision();
    assert!(matches!(
        Vault::open(f.store.clone(), id, head, b"wrong-password"),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        Vault::recover(f.store.clone(), id, head, &[5; 32]),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        Vault::recover(f.store.clone(), VaultId([1; 32]), head, &RECOVERY),
        Err(Error::Authentication)
    ));
}

#[test]
fn stale_replica_and_omitted_history_cannot_pass_an_independent_anchor() {
    let mut f = Fixture::new();
    let old = f.vault.replicate(&f.replicas).unwrap().revision();
    f.put(password(b"newer"), true);
    let latest = f.vault.revision();
    assert_ne!(old, latest);
    let replicas = f.replicas;
    let replica = replicas.into_iter().next().unwrap();
    assert!(Vault::recover(replica.store, f.vault.id(), latest, &RECOVERY).is_err());
    assert!(matches!(
        Vault::recover(f.store.clone(), f.vault.id(), old, &RECOVERY),
        Err(Error::StaleAnchor)
    ));
    f.store.fault.store(4, Ordering::SeqCst);
    assert!(matches!(
        Vault::recover(f.store.clone(), f.vault.id(), latest, &RECOVERY),
        Err(Error::Corrupt)
    ));
}

#[test]
fn corrupted_ciphertext_is_rejected_before_state_or_result_publication() {
    let mut f = Fixture::new();
    f.put(password(b"unreadable"), true);
    f.store.fault.store(3, Ordering::SeqCst);
    assert!(matches!(
        Vault::recover(f.store.clone(), f.vault.id(), f.vault.revision(), &RECOVERY),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        f.vault.replicate(&f.replicas),
        Err(Error::Corrupt)
    ));
}

#[test]
fn failed_commit_keeps_previous_state_and_unknown_commit_freezes_until_reopen() {
    let mut f = Fixture::new();
    let before = f.vault.revision();
    let id = SecretRef::random().unwrap();
    f.store.fault.store(1, Ordering::SeqCst);
    assert_eq!(
        f.vault.put(
            context(),
            request(),
            entry(id, password(b"never-committed"), true),
            None,
            &f.ward
        ),
        Err(Error::Storage)
    );
    assert_eq!(f.vault.revision(), before);
    assert!(f.vault.inspect(context(), &f.ward).unwrap().is_empty());
    let req = request();
    f.store.fault.store(2, Ordering::SeqCst);
    assert_eq!(
        f.vault.put(
            context(),
            req,
            entry(id, password(b"committed-but-unacknowledged"), true),
            None,
            &f.ward
        ),
        Err(Error::CommitUnknown)
    );
    assert_eq!(f.vault.mode(), AccessMode::Frozen);
    assert_eq!(f.vault.inspect(context(), &f.ward), Err(Error::Frozen));
    let expected = f.vault.pending_commit().unwrap();
    let vault_id = f.vault.id();
    assert_eq!(f.store.resolve(vault_id, req).unwrap(), Some(expected));
    drop(f.vault);
    drop(f.store);
    let mut reopened = Vault::open(
        GraphStore::open(f.directory.path().join("primary")).unwrap(),
        vault_id,
        expected,
        PASSWORD,
    )
    .unwrap();
    assert_eq!(
        reopened
            .put(
                context(),
                req,
                entry(id, password(b"committed-but-unacknowledged"), true),
                None,
                &f.ward
            )
            .unwrap(),
        expected
    );
    assert_eq!(reopened.inspect(context(), &f.ward).unwrap().len(), 1);
}

#[test]
fn competing_sessions_cannot_overwrite_a_newer_head() {
    let mut f = Fixture::new();
    let mut stale =
        Vault::open(f.store.clone(), f.vault.id(), f.vault.revision(), PASSWORD).unwrap();
    f.put(password(b"accepted-first"), true);
    assert_eq!(
        stale.put(
            context(),
            request(),
            entry(SecretRef::random().unwrap(), password(b"stale-write"), true),
            None,
            &f.ward
        ),
        Err(Error::StaleAnchor)
    );
    assert_eq!(f.vault.inspect(context(), &f.ward).unwrap().len(), 1);
}

#[test]
fn diverging_replica_history_is_not_resolved_by_latest_timestamp() {
    let mut f = Fixture::new();
    f.put(password(b"base"), true);
    let id = f.vault.id();
    let anchor = f.vault.replicate(&f.replicas).unwrap().revision();
    let replica = f.replicas.remove(0);
    // Trusted-host misuse deliberately creates a second writer: sync must reject it.
    let mut competing = Vault::open(replica.store, id, anchor, PASSWORD).unwrap();
    competing
        .put(
            context(),
            request(),
            entry(SecretRef::random().unwrap(), password(b"fork"), true),
            None,
            &f.ward,
        )
        .unwrap();
    f.replicas.push(Replica {
        id: replica.id,
        failure_domain: replica.failure_domain,
        store: competing.into_store(),
    });
    f.put(password(b"other-fork"), true);
    assert!(matches!(
        f.vault.replicate(&f.replicas),
        Err(Error::Conflict)
    ));
}

#[test]
fn restored_hotp_reservation_does_not_reissue_the_reserved_counter() {
    let mut f = Fixture::new();
    let secret = f.put(
        SecretInput::hotp(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            0,
        )
        .unwrap(),
        false,
    );
    let pending = f
        .vault
        .prepare_use(context(), request(), Operation::Otp { secret }, &f.ward)
        .unwrap();
    f.vault.replicate(&f.replicas).unwrap();
    let id = f.vault.id();
    let anchor = pending.revision();
    // No output has been delivered, but the protected reservation already counts.
    drop(f.vault);
    drop(f.store);
    let mut reopened = Vault::open(
        GraphStore::open(f.directory.path().join("primary")).unwrap(),
        id,
        anchor,
        PASSWORD,
    )
    .unwrap();
    let next = reopened
        .prepare_use(context(), request(), Operation::Otp { secret }, &f.ward)
        .unwrap();
    let copies = reopened.replicate(&f.replicas).unwrap();
    reopened
        .release(context(), &next, &copies, &f.ward, |out| {
            let Output::Secret(code) = out else { panic!() };
            assert_eq!(code.as_slice(), b"287082");
            Ok(())
        })
        .unwrap();
}

#[test]
fn partial_replication_resumes_and_false_acknowledgements_cannot_protect() {
    use std::sync::Arc;
    let mut f = Fixture::new();
    let replicas = vec![
        Replica {
            id: [10; 32],
            failure_domain: "fault-a".into(),
            store: Arc::new(FaultStore::open(&f.directory.path().join("fault-a"))),
        },
        Replica {
            id: [11; 32],
            failure_domain: "fault-b".into(),
            store: Arc::new(FaultStore::open(&f.directory.path().join("fault-b"))),
        },
    ];
    replicas[1].store.fault.store(5, Ordering::SeqCst);
    assert!(matches!(
        f.vault.replicate(&replicas),
        Err(Error::StaleAnchor)
    ));
    assert_eq!(replicas[1].store.head(f.vault.id()).unwrap(), None);
    f.put(password(b"protected-after-resume"), true);
    let anchor = f.vault.revision();
    replicas[1].store.fault.store(2, Ordering::SeqCst);
    assert!(matches!(
        f.vault.replicate(&replicas),
        Err(Error::CommitUnknown)
    ));
    assert_eq!(replicas[0].store.head(f.vault.id()).unwrap(), Some(anchor));
    assert_eq!(
        replicas[1].store.head(f.vault.id()).unwrap().unwrap().index,
        0
    );
    let copies = f.vault.replicate(&replicas).unwrap();
    assert_eq!(copies.revision(), anchor);
    assert_eq!(copies.copies(), 2);
    assert_eq!(replicas[1].store.head(f.vault.id()).unwrap(), Some(anchor));
}
