use super::*;
use crate::state::{Receipt, legacy::Snapshot};

struct TestWard;
impl Ward for TestWard {
    fn with_authorization<T>(
        &self,
        _: &Intent,
        action: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        action(59)
    }
}
fn credential(id: SecretRef, context: Context) -> Entry {
    Entry::new(
        id,
        "synthetic legacy credential".into(),
        "https://example.invalid".into(),
        context.policy,
        true,
        SecretInput::password(Zeroizing::new(b"legacy-test-secret".to_vec())).unwrap(),
    )
    .unwrap()
}

#[test]
fn legacy_snapshots_extend_with_deltas_preserving_receipts_and_rejecting_downgrade() {
    let directory = tempfile::tempdir().unwrap();
    let store = GraphStore::open(directory.path().join("primary")).unwrap();
    let id = VaultId([1; 32]);
    let secret = SecretRef([2; 16]);
    let context = Context {
        actor: ActorId([3; 32]),
        policy: PolicyRef([4; 32]),
    };
    let password = b"synthetic-legacy-unlock";
    let recovery = [5; 32];
    let (header, keys) = Header::create(id, password, &recovery).unwrap();
    let create = RequestId([6; 32]);
    let put = RequestId([7; 32]);
    let mut legacy = Snapshot::empty(create, context);
    let packet = Packet::seal(
        header.clone(),
        &keys,
        create,
        None,
        legacy.encode().unwrap(),
    )
    .unwrap();
    let genesis = store
        .append(id, create, None, packet.encode().unwrap())
        .unwrap();
    let mut entry = credential(secret, context);
    // Reproduce the v1 put request encoding independently of the current writer.
    let mut operation = Encoder::new();
    operation.byte(1);
    entry.encode(&mut operation).unwrap();
    operation.byte(0);
    let mut input = Encoder::new();
    input.fixed(&id.0);
    input.fixed(&put.0);
    input.fixed(&context.actor.0);
    input.fixed(&context.policy.0);
    input.bytes(&operation.0).unwrap();
    legacy.request = put;
    legacy.fingerprint = keys.fingerprint(&input.0).unwrap();
    legacy.receipt = Receipt {
        context,
        secret: None,
        entry_version: 0,
        operation: operation.0,
        output: Zeroizing::new(vec![]),
    };
    entry.info.version = 1;
    legacy.entries.insert(secret, entry);
    let packet = Packet::seal(
        header.clone(),
        &keys,
        put,
        Some(genesis),
        legacy.encode().unwrap(),
    )
    .unwrap();
    let old_bytes = packet.encode().unwrap();
    let old_head = store
        .append(id, put, Some(genesis), old_bytes.clone())
        .unwrap();
    let mut vault = Vault::open(store, id, old_head, password).unwrap();
    let ward = TestWard;
    vault
        .put(
            context,
            RequestId([8; 32]),
            credential(SecretRef([9; 16]), context),
            None,
            &ward,
        )
        .unwrap();
    assert_eq!(
        vault
            .put(context, put, credential(secret, context), None, &ward)
            .unwrap(),
        old_head
    );
    assert_eq!(vault.store().read(old_head).unwrap().bytes, old_bytes);
    let pending = vault
        .prepare_use(
            context,
            RequestId([10; 32]),
            Operation::Reveal {
                secret,
                surface: "synthetic-protected-surface".into(),
            },
            &ward,
        )
        .unwrap();
    let replicas = vec![
        Replica {
            id: [11; 32],
            failure_domain: "a".into(),
            store: GraphStore::open(directory.path().join("a")).unwrap(),
        },
        Replica {
            id: [12; 32],
            failure_domain: "b".into(),
            store: GraphStore::open(directory.path().join("b")).unwrap(),
        },
    ];
    let copies = vault.replicate(&replicas).unwrap();
    vault
        .release(context, &pending, &copies, &ward, |output| {
            let Output::Secret(bytes) = output else {
                panic!()
            };
            assert_eq!(bytes.as_slice(), b"legacy-test-secret");
            Ok(())
        })
        .unwrap();
    let anchor = vault.revision();
    let restored = Vault::recover(vault.into_store(), id, anchor, &recovery).unwrap();
    assert_eq!(restored.inspect(context, &ward).unwrap().len(), 2);
    // Authenticated legacy data must not overwrite an already accepted v2 tail.
    let downgraded = RequestId([13; 32]);
    legacy.request = downgraded;
    let packet = Packet::seal(
        header,
        &keys,
        downgraded,
        Some(anchor),
        legacy.encode().unwrap(),
    )
    .unwrap();
    let store = restored.into_store();
    let invalid_head = store
        .append(id, downgraded, Some(anchor), packet.encode().unwrap())
        .unwrap();
    assert!(matches!(
        Vault::recover(store, id, invalid_head, &recovery),
        Err(Error::Corrupt)
    ));
}
