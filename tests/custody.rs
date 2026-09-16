#![cfg(feature = "graph-store")]
mod support;
use support::*;
use vault::*;
use zeroize::Zeroizing;

#[test]
fn records_survive_reopen_and_database_contains_only_ciphertext() {
    let mut f = Fixture::new();
    let id = f.put(password(b"uniquely-searchable-synthetic-password"), true);
    let values = f.store.history(f.vault.id()).unwrap();
    for head in values {
        let bytes = f.store.read(head).unwrap().bytes;
        for text in [
            b"uniquely-searchable-synthetic-password".as_slice(),
            b"synthetic private label",
            b"https://example.invalid",
        ] {
            assert!(!bytes.windows(text.len()).any(|w| w == text));
        }
    }
    let anchor = f.vault.revision();
    let vault_id = f.vault.id();
    drop(f.vault);
    drop(f.store);
    let graph = GraphStore::open(f.directory.path().join("primary")).unwrap();
    let mut reopened = Vault::open(graph, vault_id, anchor, PASSWORD).unwrap();
    let pending = reopened
        .prepare_use(
            context(),
            request(),
            Operation::Reveal {
                secret: id,
                surface: "protected-test".into(),
            },
            &f.ward,
        )
        .unwrap();
    let copies = reopened.replicate(&f.replicas).unwrap();
    reopened
        .release(context(), &pending, &copies, &f.ward, |out| {
            let Output::Secret(bytes) = out else {
                panic!("expected credential")
            };
            assert_eq!(bytes.as_slice(), b"uniquely-searchable-synthetic-password");
            Ok(())
        })
        .unwrap();
}

#[test]
fn two_copies_are_required_and_current_ward_guards_delivery() {
    let mut f = Fixture::new();
    let id = f.put(password(b"synthetic-password"), true);
    let old_copies = f.vault.replicate(&f.replicas).unwrap();
    let pending = f
        .vault
        .prepare_use(
            context(),
            request(),
            Operation::Reveal {
                secret: id,
                surface: "protected-test".into(),
            },
            &f.ward,
        )
        .unwrap();
    assert_eq!(
        f.vault
            .release(context(), &pending, &old_copies, &f.ward, |_| Ok(())),
        Err(Error::ReplicationRequired)
    );
    assert!(matches!(
        f.vault.replicate(&f.replicas[..1]),
        Err(Error::ReplicationRequired)
    ));
    let copies = f.vault.replicate(&f.replicas).unwrap();
    f.ward.state.write().unwrap().0 = false;
    assert_eq!(
        f.vault
            .release(context(), &pending, &copies, &f.ward, |_| Ok(())),
        Err(Error::Denied)
    );
    f.ward.state.write().unwrap().0 = true;
    f.vault
        .release(context(), &pending, &copies, &f.ward, |_| {
            assert!(
                f.ward.state.try_write().is_err(),
                "permission guard must cover delivery"
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn exact_retry_returns_original_revision_and_conflicting_input_rejects() {
    let mut f = Fixture::new();
    let id = SecretRef::random().unwrap();
    let req = request();
    let revision = f
        .vault
        .put(
            context(),
            req,
            entry(id, password(b"first"), true),
            None,
            &f.ward,
        )
        .unwrap();
    f.put(password(b"later"), false);
    let latest = f.vault.revision();
    assert_eq!(
        f.vault
            .put(
                context(),
                req,
                entry(id, password(b"first"), true),
                None,
                &f.ward
            )
            .unwrap(),
        revision
    );
    assert_eq!(f.vault.revision(), latest);
    assert_eq!(
        f.vault.put(
            context(),
            req,
            entry(id, password(b"changed"), true),
            None,
            &f.ward
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn typed_roots_cannot_be_revealed_delivered_or_retagged() {
    let mut f = Fixture::new();
    let id = f.put(
        SecretInput::domain_root(Zeroizing::new([7; 32])).unwrap(),
        false,
    );
    for operation in [
        Operation::Reveal {
            secret: id,
            surface: "test".into(),
        },
        Operation::Deliver {
            secret: id,
            destination: "https://example.invalid".into(),
        },
    ] {
        assert!(matches!(
            f.vault
                .prepare_use(context(), request(), operation, &f.ward),
            Err(Error::Denied)
        ));
    }
    let version = f.vault.inspect(context(), &f.ward).unwrap()[0].version;
    assert_eq!(
        f.vault.put(
            context(),
            request(),
            entry(id, password(b"not-a-root"), true),
            Some(version),
            &f.ward
        ),
        Err(Error::Conflict)
    );
    assert!(
        Entry::new(
            SecretRef::random().unwrap(),
            "root".into(),
            "test".into(),
            context().policy,
            true,
            SecretInput::generate_domain_root().unwrap()
        )
        .is_err()
    );
}

#[test]
fn redirect_different_actor_lock_and_replaced_entry_block_release() {
    let mut f = Fixture::new();
    let id = f.put(password(b"first"), true);
    assert!(matches!(
        f.vault.prepare_use(
            context(),
            request(),
            Operation::Deliver {
                secret: id,
                destination: "https://attacker.invalid".into()
            },
            &f.ward
        ),
        Err(Error::Denied)
    ));
    let pending = f
        .vault
        .prepare_use(
            context(),
            request(),
            Operation::Reveal {
                secret: id,
                surface: "test".into(),
            },
            &f.ward,
        )
        .unwrap();
    let copies = f.vault.replicate(&f.replicas).unwrap();
    let stranger = Context {
        actor: ActorId([99; 32]),
        ..context()
    };
    assert!(
        f.vault
            .release(stranger, &pending, &copies, &f.ward, |_| Ok(()))
            .is_err()
    );
    let version = f.vault.inspect(context(), &f.ward).unwrap()[0].version;
    f.vault
        .put(
            context(),
            request(),
            entry(id, password(b"replacement"), true),
            Some(version),
            &f.ward,
        )
        .unwrap();
    assert_eq!(
        f.vault
            .release(context(), &pending, &copies, &f.ward, |_| Ok(())),
        Err(Error::Denied)
    );
    f.vault.lock();
    assert_eq!(f.vault.inspect(context(), &f.ward), Err(Error::Locked));
}

#[test]
fn tombstone_cannot_be_resurrected_and_delete_retry_does_not_advance() {
    let mut f = Fixture::new();
    let id = f.put(password(b"deleted"), true);
    let version = f.vault.inspect(context(), &f.ward).unwrap()[0].version;
    let req = request();
    let deleted = f
        .vault
        .delete(context(), req, id, version, &f.ward)
        .unwrap();
    assert_eq!(
        f.vault
            .delete(context(), req, id, version, &f.ward)
            .unwrap(),
        deleted
    );
    assert_eq!(
        f.vault.put(
            context(),
            request(),
            entry(id, password(b"resurrection"), true),
            None,
            &f.ward
        ),
        Err(Error::Conflict)
    );
    assert!(f.vault.inspect(context(), &f.ward).unwrap().is_empty());
}

#[test]
fn duplicate_failure_domains_are_not_counted_as_independent_copies() {
    let mut f = Fixture::new();
    f.replicas[1].failure_domain = f.replicas[0].failure_domain.clone();
    assert!(matches!(
        f.vault.replicate(&f.replicas),
        Err(Error::InvalidInput)
    ));
}
