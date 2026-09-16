#![cfg(feature = "graph-store")]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use vault::*;

fn secret_id(n: u64) -> SecretRef {
    let mut id = [0; 16];
    id[8..].copy_from_slice(&n.to_be_bytes());
    SecretRef(id)
}

#[test]
fn thousands_of_entities_and_revisions_survive_paging_replication_and_device_loss() {
    // More than both old count limits; raw secret values alone exceed the old
    // 4 MiB aggregate snapshot budget. These are synthetic records on real Fjall.
    const COUNT: u64 = 4352;
    let mut f = Fixture::new();
    let bytes = vec![0x53; 1024];
    let first_request = request();
    let mut first_head = None;
    for n in 0..COUNT {
        let head = f
            .vault
            .put(
                context(),
                if n == 0 { first_request } else { request() },
                entry(secret_id(n), password(&bytes), true),
                None,
                &f.ward,
            )
            .unwrap();
        if n == 0 {
            first_head = Some(head);
        }
        if n % 1024 == 0 {
            eprintln!("synthetic capacity test: {n} entries committed");
        }
    }
    assert_eq!(f.vault.revision().index, COUNT);
    assert!(
        f.store.read(f.vault.revision()).unwrap().bytes.len() < 8192,
        "one-entry change size must not grow with the catalog"
    );
    let id = f.vault.id();
    let anchor = f.vault.revision();

    // Page boundaries cannot hide a missing row or a withheld suffix.
    for mode in [6, 7] {
        f.store.fault.store(mode, Ordering::SeqCst);
        assert!(matches!(
            Vault::recover(f.store.clone(), id, anchor, &RECOVERY),
            Err(Error::Corrupt)
        ));
    }
    f.store.fault.store(0, Ordering::SeqCst);
    drop(f.vault);
    drop(f.store);
    let store = GraphStore::open(f.directory.path().join("primary")).unwrap();
    let mut vault = Vault::open(store, id, anchor, PASSWORD).unwrap();
    assert_eq!(
        vault
            .put(
                context(),
                first_request,
                entry(secret_id(0), password(&bytes), true),
                None,
                &f.ward
            )
            .unwrap(),
        first_head.unwrap()
    );
    vault
        .put(
            context(),
            request(),
            entry(secret_id(COUNT), password(&bytes), true),
            None,
            &f.ward,
        )
        .unwrap();
    vault
        .delete(context(), request(), secret_id(1), 2, &f.ward)
        .unwrap();
    assert_eq!(
        vault.put(
            context(),
            request(),
            entry(secret_id(1), password(&bytes), true),
            None,
            &f.ward
        ),
        Err(Error::Conflict)
    );
    let pending = vault
        .prepare_use(
            context(),
            request(),
            Operation::Reveal {
                secret: secret_id(0),
                surface: "synthetic-protected-surface".into(),
            },
            &f.ward,
        )
        .unwrap();
    let anchor = vault.revision();
    // Ciphertext replication is independent of unlocked custody.
    vault.lock();
    let copies = vault.replicate(&f.replicas).unwrap();
    assert_eq!(copies.revision(), anchor);
    let mut total = 0;
    let mut after = None;
    loop {
        let page = vault.store().history_page(id, after, 97).unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 97);
        total += page.len();
        after = page.last().map(|r| r.index);
    }
    assert_eq!(total as u64, anchor.index + 1);
    let vault = Vault::open(vault.into_store(), id, anchor, PASSWORD).unwrap();
    vault
        .release(context(), &pending, &copies, &f.ward, |output| {
            let Output::Secret(value) = output else {
                panic!()
            };
            assert_eq!(value.as_slice(), bytes);
            Ok(())
        })
        .unwrap();
    drop(vault);
    drop(f.replicas);
    std::fs::remove_dir_all(f.directory.path().join("primary")).unwrap();
    std::fs::remove_dir_all(f.directory.path().join("a")).unwrap();
    let restored = Vault::recover(
        GraphStore::open(f.directory.path().join("b")).unwrap(),
        id,
        anchor,
        &RECOVERY,
    )
    .unwrap();
    assert_eq!(restored.mode(), AccessMode::RecoveryReadOnly);
    let mut ids = Vec::new();
    let mut after = None;
    loop {
        let page = restored
            .inspect_page(context(), after, 127, &f.ward)
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 127);
        after = page.last().map(|e| e.id);
        ids.extend(page.into_iter().map(|e| e.id));
    }
    assert_eq!(ids.len() as u64, COUNT);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert!(!ids.contains(&secret_id(1)));
    assert!(ids.contains(&secret_id(COUNT)));
    eprintln!(
        "verified: {} live entries, {} revisions, {} raw secret bytes; source and one copy removed",
        ids.len(),
        anchor.index + 1,
        COUNT * bytes.len() as u64
    );
}
