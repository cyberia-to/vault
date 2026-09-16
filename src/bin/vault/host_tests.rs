use super::*;
use crate::owner::{Grant, Owner};
use vault::{Entry, SecretInput, SecretRef, Vault};
use zeroize::Zeroizing;

fn create(host: &Host) -> Vault<Arc<JournaledStore>> {
    let state = host.state().unwrap();
    let ward = Owner {
        vault: VaultId(state.vault),
        context: state.context(),
        request: RequestId([1; 32]),
        grant: Grant::Create,
    };
    Vault::create(
        host.store.clone(),
        ward.vault,
        ward.request,
        ward.context,
        b"synthetic-unlock",
        &[9; 32],
        &ward,
    )
    .unwrap()
}

#[test]
fn restart_authenticates_remembered_commits_including_initial_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let initial = {
        let host = Host::open(&path, true).unwrap();
        let vault = create(&host);
        assert!(host.state().unwrap().anchor.is_none());
        assert!(host.state().unwrap().pending.is_some());
        vault.revision()
        // Crash point: DB commit exists, finalized host checkpoint does not.
    };
    let next = {
        let host = Host::open(&path, false).unwrap();
        let state = host.state().unwrap();
        assert_eq!(host.opening_anchor().unwrap(), initial);
        let mut vault = Vault::open(
            host.store.clone(),
            VaultId(state.vault),
            initial,
            b"synthetic-unlock",
        )
        .unwrap();
        host.settle(vault.revision()).unwrap();
        let entry = Entry::new(
            SecretRef([4; 16]),
            "test".into(),
            "test".into(),
            state.context().policy,
            false,
            SecretInput::password(Zeroizing::new(b"synthetic-value".to_vec())).unwrap(),
        )
        .unwrap();
        let ward = Owner {
            vault: vault.id(),
            context: state.context(),
            request: RequestId([2; 32]),
            grant: Grant::Put(entry.info().clone()),
        };
        vault
            .put(ward.context, ward.request, entry, None, &ward)
            .unwrap();
        assert_eq!(host.state().unwrap().anchor.unwrap().index, 0);
        vault.revision()
    };
    let host = Host::open(&path, false).unwrap();
    let state = host.state().unwrap();
    assert_eq!(host.opening_anchor().unwrap(), next);
    let vault = Vault::open(
        host.store.clone(),
        VaultId(state.vault),
        next,
        b"synthetic-unlock",
    )
    .unwrap();
    host.settle(vault.revision()).unwrap();
    let ward = Owner {
        vault: vault.id(),
        context: state.context(),
        request: RequestId([0; 32]),
        grant: Grant::Inspect,
    };
    assert_eq!(vault.inspect(ward.context, &ward).unwrap().len(), 1);
    assert!(host.state().unwrap().pending.is_none());
}

#[test]
fn uncommitted_candidate_keeps_prior_anchor_and_host_lock_is_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let host = Host::open(&path, true).unwrap();
    assert!(Host::open(&path, false).is_err());
    let vault = create(&host);
    host.settle(vault.revision()).unwrap();
    let mut state = host.state().unwrap();
    state.pending = Some(Pending {
        request: [7; 32],
        previous: state.anchor,
        candidate: Anchor {
            index: 1,
            commit: [8; 32],
        },
    });
    host.save(state).unwrap();
    assert_eq!(host.opening_anchor().unwrap(), vault.revision());
    host.settle(vault.revision()).unwrap();
    assert!(host.state().unwrap().pending.is_none());
}

#[test]
fn init_preserves_data_when_host_metadata_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let host = Host::open(&path, true).unwrap();
    let vault = create(&host);
    host.settle(vault.revision()).unwrap();
    let anchor = vault.revision();
    let id = vault.id();
    drop(vault);
    drop(host);
    std::fs::remove_file(path.join("host.json")).unwrap();
    assert!(Host::open(&path, true).is_err());
    assert!(!path.join("host.json").exists());
    let graph = GraphStore::open(path.join("graph")).unwrap();
    assert_eq!(graph.head(id).unwrap(), Some(anchor));
}
