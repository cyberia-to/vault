#![cfg(feature = "graph-store")]
mod support;

use cybergraph::application::{ApplicationGraph, Backend, Database, Head, Proposal};
use cybergraph::content::Codec;
use support::*;
use vault::*;

fn graph_head(revision: Revision) -> Head {
    Head {
        index: revision.index,
        commit: revision.commit,
    }
}

/// Transfer deliberately uses only ApplicationGraph at the receiver: no Vault
/// writer, decryption, custody grant or custom database schema is involved.
#[test]
fn ciphertext_and_original_receipts_survive_plain_cybergraph_copy_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source_db = Database::open(directory.path().join("source"), Backend::Ssd).unwrap();
    let source = ApplicationGraph::from_database(source_db.clone());
    let ward = TestWard::new();
    let id = VaultId::random().unwrap();
    let created = request();
    let mut vault = Vault::create(
        GraphStore::from_database(source_db.clone()),
        id,
        created,
        context(),
        PASSWORD,
        &RECOVERY,
        &ward,
    )
    .unwrap();
    let mut receipts = vec![(created, vault.revision())];
    let inserted = request();
    let secret = SecretRef::random().unwrap();
    let committed = vault
        .put(
            context(),
            inserted,
            entry(secret, password(b"synthetic-graph-boundary-secret"), true),
            None,
            &ward,
        )
        .unwrap();
    receipts.push((inserted, committed));
    let used = request();
    let pending = vault
        .prepare_use(
            context(),
            used,
            Operation::Reveal {
                secret,
                surface: "synthetic-protected-surface".into(),
            },
            &ward,
        )
        .unwrap();
    receipts.push((used, pending.revision()));
    let anchor = vault.revision();
    let expected = vault.inspect(context(), &ward).unwrap();
    vault.lock();

    assert_eq!(
        source.history(&id.0, None, 100).unwrap(),
        receipts
            .iter()
            .map(|(_, r)| graph_head(*r))
            .collect::<Vec<_>>()
    );
    assert_eq!(source.head(&id.0).unwrap(), Some(graph_head(anchor)));
    let receiver = ApplicationGraph::open(directory.path().join("receiver")).unwrap();
    let mut previous = None;
    for (request, revision) in &receipts {
        let content = source.get(&revision.commit).unwrap().unwrap();
        assert_eq!(content.codec(), Codec::Blob);
        assert!(
            !content
                .bytes()
                .windows(b"synthetic-graph-boundary-secret".len())
                .any(|part| part == b"synthetic-graph-boundary-secret")
        );
        assert_eq!(
            source.resolve(&id.0, &request.0).unwrap(),
            Some(graph_head(*revision))
        );
        let proposal = Proposal {
            namespace: id.0,
            request: request.0,
            expected: previous,
            head: graph_head(*revision),
            content: vec![content],
            required: vec![],
            claims: vec![],
        };
        let accepted = receiver.commit(&proposal, |_| Ok(())).unwrap();
        assert_eq!(accepted, graph_head(*revision));
        // The graph owns exact retry receipts even without a Vault instance.
        assert_eq!(receiver.commit(&proposal, |_| Ok(())).unwrap(), accepted);
        previous = Some(accepted);
    }
    assert_eq!(receiver.head(&id.0).unwrap(), Some(graph_head(anchor)));
    drop(receiver);
    drop(vault);
    drop(source);
    drop(source_db);
    std::fs::remove_dir_all(directory.path().join("source")).unwrap();

    let reopened = GraphStore::open(directory.path().join("receiver")).unwrap();
    for (request, revision) in receipts {
        assert_eq!(reopened.resolve(id, request).unwrap(), Some(revision));
    }
    let restored = Vault::recover(reopened, id, anchor, &RECOVERY).unwrap();
    assert_eq!(restored.mode(), AccessMode::RecoveryReadOnly);
    assert_eq!(restored.inspect(context(), &ward).unwrap(), expected);
}

#[test]
fn graph_closure_checks_and_vault_receipt_checks_are_distinct_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(directory.path().join("source"), Backend::Ssd).unwrap();
    let graph = ApplicationGraph::from_database(db.clone());
    let id = VaultId::random().unwrap();
    let original = request();
    let ward = TestWard::new();
    let vault = Vault::create(
        GraphStore::from_database(db),
        id,
        original,
        context(),
        PASSWORD,
        &RECOVERY,
        &ward,
    )
    .unwrap();
    let anchor = vault.revision();
    let target = ApplicationGraph::open(directory.path().join("target")).unwrap();
    let mut proposal = Proposal {
        namespace: id.0,
        request: request().0,
        expected: None,
        head: graph_head(anchor),
        content: vec![],
        required: vec![],
        claims: vec![],
    };
    assert!(matches!(
        target.commit(&proposal, |_| Ok(())),
        Err(cybergraph::application::Error::MissingContent(_))
    ));
    assert_eq!(target.head(&id.0).unwrap(), None);

    // An opaque Blob has no graph-level knowledge of the Vault receipt inside.
    // This models a trusted caller incorrectly binding a copied packet to a new
    // request. Generic graph validity must never be called Vault validity.
    proposal
        .content
        .push(graph.get(&anchor.commit).unwrap().unwrap());
    target.commit(&proposal, |_| Ok(())).unwrap();
    assert_eq!(target.resolve(&id.0, &original.0).unwrap(), None);
    drop(target);
    assert!(matches!(
        Vault::recover(
            GraphStore::open(directory.path().join("target")).unwrap(),
            id,
            anchor,
            &RECOVERY
        ),
        Err(Error::Corrupt)
    ));
}
