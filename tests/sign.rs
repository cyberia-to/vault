#![cfg(feature = "graph-store")]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use vault::*;
use zeroize::Zeroizing;

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn domain(f: &mut Fixture) -> (SignRequest, mudra::SigningKey) {
    let root = f.put(
        SecretInput::domain_root(Zeroizing::new([7; 32])).unwrap(),
        false,
    );
    let key = mudra::domain::DomainKey::derive(&[7; 32], "example.test", "bostrom").unwrap();
    (
        SignRequest {
            key: NeuronKeyRef {
                root,
                derivation: Derivation::Domain {
                    domain: "example.test".into(),
                    hrp: "bostrom".into(),
                },
            },
            subject: key.native,
            statement: [8; 32],
        },
        key.signing_key().clone(),
    )
}

// Assemble the pre-existing envelope independently of mudra::neuron::sign.
fn legacy(key: &mudra::SigningKey, statement: [u8; 32]) -> Vec<u8> {
    let public = mudra::cosmos::compressed(key.verifying_key());
    let address = mudra::cosmos::address(&public, "neuron").unwrap();
    let mut message = b"cyber:neuron:authority:v1:".to_vec();
    message.extend(statement);
    let mut evidence = b"NSIG1".to_vec();
    evidence.extend(public);
    evidence.extend(mudra::claim::sign_arbitrary(key, &address, &message));
    evidence
}

fn release(f: &Fixture, pending: &PendingUse, expected: &SignRequest) -> Vec<u8> {
    let copies = f.vault.replicate(&f.replicas).unwrap();
    f.vault
        .release(context(), pending, &copies, &f.ward, |output| {
            let Output::Signature { request, evidence } = output else {
                panic!()
            };
            assert_eq!(&request, expected);
            assert!(mudra::neuron::verify_statement(
                request.subject,
                request.statement,
                &evidence
            ));
            Ok(evidence)
        })
        .unwrap()
}

#[test]
fn both_derivations_preserve_legacy_bytes_and_retry_after_reopen() {
    let mut f = Fixture::new();
    let (domain, domain_key) = domain(&mut f);
    let root = f.put(SecretInput::spell(WORDS, "").unwrap(), false);
    let key = mudra::spell::cosmos_key(WORDS, "").unwrap();
    let cosmos = SignRequest {
        key: NeuronKeyRef {
            root,
            derivation: Derivation::Cosmos {
                path: mudra::spell::COSMOS_PATH.into(),
                hrp: "cosmos".into(),
            },
        },
        subject: mudra::claim::neuron_of(&mudra::cosmos::compressed(key.verifying_key())),
        statement: [8; 32],
    };
    for (signing, key) in [(domain, domain_key), (cosmos, key)] {
        let req = request();
        let first = f
            .vault
            .sign(context(), req, signing.clone(), &f.ward)
            .unwrap();
        let evidence = release(&f, &first, &signing);
        assert_eq!(evidence, legacy(&key, signing.statement));
        let mut other_hrp = signing.clone();
        match &mut other_hrp.key.derivation {
            Derivation::Cosmos { hrp, .. } | Derivation::Domain { hrp, .. } => {
                *hrp = "different".into()
            }
        }
        let other = f
            .vault
            .sign(context(), request(), other_hrp.clone(), &f.ward)
            .unwrap();
        assert_eq!(release(&f, &other, &other_hrp), evidence);
        let anchor = f.vault.revision();
        f.vault = Vault::open(f.store.clone(), f.vault.id(), anchor, PASSWORD).unwrap();
        let retry = f
            .vault
            .sign(context(), req, signing.clone(), &f.ward)
            .unwrap();
        assert_eq!(retry.revision(), first.revision());
        assert_eq!(f.vault.revision(), anchor);
        assert_eq!(release(&f, &retry, &signing), evidence);
        let mut different = signing.clone();
        different.statement[0] ^= 1;
        assert!(matches!(
            f.vault.sign(context(), req, different, &f.ward),
            Err(Error::Conflict)
        ));
        assert!(matches!(
            f.vault.sign(context(), req, other_hrp, &f.ward),
            Err(Error::Conflict)
        ));
    }
}

#[test]
fn wrong_subject_kind_profile_and_denied_prepare_do_not_commit() {
    let mut f = Fixture::new();
    let (signing, _) = domain(&mut f);
    let password = f.put(password(b"synthetic-password"), false);
    let head = f.vault.revision();
    let mut bad = signing.clone();
    bad.subject = [99; 32];
    assert!(matches!(
        f.vault.sign(context(), request(), bad, &f.ward),
        Err(Error::Denied)
    ));
    let mut bad = signing.clone();
    bad.key.root = password;
    assert!(matches!(
        f.vault.sign(context(), request(), bad, &f.ward),
        Err(Error::Denied)
    ));
    let mut bad = signing.clone();
    bad.key.derivation = Derivation::Cosmos {
        path: mudra::spell::COSMOS_PATH.into(),
        hrp: "neuron".into(),
    };
    assert!(matches!(
        f.vault.sign(context(), request(), bad, &f.ward),
        Err(Error::Denied)
    ));
    f.ward.state.write().unwrap().0 = false;
    assert!(matches!(
        f.vault.sign(context(), request(), signing, &f.ward),
        Err(Error::Denied)
    ));
    assert_eq!(f.vault.revision(), head);
}

#[test]
fn release_requires_current_copies_permission_and_root_version() {
    let mut f = Fixture::new();
    let (signing, _) = domain(&mut f);
    let stale_copies = f.vault.replicate(&f.replicas).unwrap();
    let pending = f
        .vault
        .sign(context(), request(), signing.clone(), &f.ward)
        .unwrap();
    assert!(matches!(
        f.vault.replicate(&f.replicas[..1]),
        Err(Error::ReplicationRequired)
    ));
    assert_eq!(
        f.vault
            .release(context(), &pending, &stale_copies, &f.ward, |_| panic!(
                "released"
            )),
        Err::<(), _>(Error::ReplicationRequired)
    );
    let copies = f.vault.replicate(&f.replicas).unwrap();
    f.ward.state.write().unwrap().0 = false;
    assert_eq!(
        f.vault
            .release(context(), &pending, &copies, &f.ward, |_| panic!(
                "released"
            )),
        Err::<(), _>(Error::Denied)
    );
    f.ward.state.write().unwrap().0 = true;
    f.vault
        .put(
            context(),
            request(),
            entry(
                signing.key.root,
                SecretInput::domain_root(Zeroizing::new([9; 32])).unwrap(),
                false,
            ),
            Some(1),
            &f.ward,
        )
        .unwrap();
    assert_eq!(
        f.vault
            .release(context(), &pending, &copies, &f.ward, |_| panic!(
                "released"
            )),
        Err::<(), _>(Error::Denied)
    );
    let recovered =
        Vault::recover(f.store.clone(), f.vault.id(), f.vault.revision(), &RECOVERY).unwrap();
    assert_eq!(
        recovered.release(context(), &pending, &copies, &f.ward, |_| panic!(
            "released"
        )),
        Err::<(), _>(Error::ReadOnly)
    );
}

#[test]
fn uncertain_sign_freezes_then_reconciles_the_original_receipt() {
    let mut f = Fixture::new();
    let (signing, key) = domain(&mut f);
    let req = request();
    f.store.fault.store(2, Ordering::SeqCst);
    assert!(matches!(
        f.vault.sign(context(), req, signing.clone(), &f.ward),
        Err(Error::CommitUnknown)
    ));
    assert_eq!(f.vault.mode(), AccessMode::Frozen);
    let candidate = f.vault.pending_commit().unwrap();
    assert_eq!(f.store.resolve(f.vault.id(), req).unwrap(), Some(candidate));
    f.vault = Vault::open(f.store.clone(), f.vault.id(), candidate, PASSWORD).unwrap();
    let retry = f
        .vault
        .sign(context(), req, signing.clone(), &f.ward)
        .unwrap();
    assert_eq!(retry.revision(), candidate);
    assert_eq!(
        release(&f, &retry, &signing),
        legacy(&key, signing.statement)
    );
}
