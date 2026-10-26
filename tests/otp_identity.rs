#![cfg(feature = "graph-store")]
mod support;
use support::*;
use vault::*;
use zeroize::Zeroizing;

#[test]
fn hotp_reserves_once_and_retry_keeps_the_original_code_after_other_use() {
    let mut f = Fixture::new();
    let id = f.put(
        SecretInput::hotp(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            0,
        )
        .unwrap(),
        false,
    );
    let req = request();
    let op = Operation::Otp { secret: id };
    let first = f
        .vault
        .prepare_use(context(), req, op.clone(), &f.ward)
        .unwrap();
    let second = f
        .vault
        .prepare_use(context(), request(), op.clone(), &f.ward)
        .unwrap();
    let retry = f.vault.prepare_use(context(), req, op, &f.ward).unwrap();
    assert_eq!(first.revision(), retry.revision());
    let copies = f.vault.replicate(&f.replicas).unwrap();
    for (pending, expected) in [(first, "755224"), (second, "287082"), (retry, "755224")] {
        f.vault
            .release(context(), &pending, &copies, &f.ward, |out| {
                let Output::Secret(code) = out else { panic!() };
                assert_eq!(code.as_slice(), expected.as_bytes());
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(
        f.use_bytes(Operation::Otp { secret: id }).as_slice(),
        b"359152"
    );
}

#[test]
fn recovery_codes_are_reserved_once_and_exhaustion_is_durable() {
    let mut f = Fixture::new();
    let id = f.put(
        SecretInput::recovery_codes(vec![
            Zeroizing::new(b"synthetic-code-a".to_vec()),
            Zeroizing::new(b"synthetic-code-b".to_vec()),
        ])
        .unwrap(),
        false,
    );
    assert_eq!(
        f.use_bytes(Operation::RecoveryCode { secret: id })
            .as_slice(),
        b"synthetic-code-a"
    );
    assert_eq!(
        f.use_bytes(Operation::RecoveryCode { secret: id })
            .as_slice(),
        b"synthetic-code-b"
    );
    assert!(matches!(
        f.vault.prepare_use(
            context(),
            request(),
            Operation::RecoveryCode { secret: id },
            &f.ward
        ),
        Err(Error::Exhausted)
    ));
    let id_vault = f.vault.id();
    let anchor = f.vault.revision();
    drop(f.vault);
    let mut reopened = Vault::open(f.store.clone(), id_vault, anchor, PASSWORD).unwrap();
    assert!(matches!(
        reopened.prepare_use(
            context(),
            request(),
            Operation::RecoveryCode { secret: id },
            &f.ward
        ),
        Err(Error::Exhausted)
    ));
}

#[test]
fn totp_uses_ward_time_and_expired_receipt_does_not_mint_a_new_code() {
    let mut f = Fixture::new();
    let id = f.put(
        SecretInput::totp(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            8,
            30,
        )
        .unwrap(),
        false,
    );
    let req = request();
    let pending = f
        .vault
        .prepare_use(context(), req, Operation::Otp { secret: id }, &f.ward)
        .unwrap();
    let copies = f.vault.replicate(&f.replicas).unwrap();
    f.vault
        .release(context(), &pending, &copies, &f.ward, |out| {
            let Output::Secret(code) = out else { panic!() };
            assert_eq!(code.as_slice(), b"94287082");
            Ok(())
        })
        .unwrap();
    f.ward.state.write().unwrap().1 = 60;
    assert_eq!(
        f.vault
            .release(context(), &pending, &copies, &f.ward, |_| Ok(())),
        Err(Error::Denied)
    );
    assert_eq!(
        f.vault
            .prepare_use(context(), req, Operation::Otp { secret: id }, &f.ward)
            .unwrap()
            .revision(),
        pending.revision()
    );
}

#[test]
fn derive_neuron_preserves_mudra_bridge_and_domain_public_bytes() {
    let mut f = Fixture::new();
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let spell = f.put(SecretInput::spell(words, "").unwrap(), false);
    let domain = f.put(
        SecretInput::domain_root(Zeroizing::new([7; 32])).unwrap(),
        false,
    );
    let profiles = [
        NeuronKeyRef {
            root: spell,
            derivation: Derivation::Cosmos {
                path: mudra::spell::COSMOS_PATH.into(),
                hrp: "cosmos".into(),
            },
        },
        NeuronKeyRef {
            root: domain,
            derivation: Derivation::Domain {
                domain: "example.com".into(),
                hrp: "lytics".into(),
            },
        },
    ];
    for profile in profiles {
        let (expected_public, expected_address) = match &profile.derivation {
            Derivation::Cosmos { hrp, .. } => {
                let key = mudra::spell::cosmos_key(words, "").unwrap();
                let pk = mudra::cosmos::compressed(key.verifying_key());
                (pk, mudra::cosmos::address(&pk, hrp).unwrap())
            }
            Derivation::Domain { domain, hrp } => {
                let key = mudra::domain::DomainKey::derive(&[7; 32], domain, hrp).unwrap();
                (key.pubkey, key.bech32)
            }
        };
        let pending = f
            .vault
            .derive_neuron(context(), request(), profile.clone(), &f.ward)
            .unwrap();
        let copies = f.vault.replicate(&f.replicas).unwrap();
        f.vault
            .release(context(), &pending, &copies, &f.ward, |out| {
                let Output::Neuron {
                    key,
                    subject,
                    public_key,
                    address,
                } = out
                else {
                    panic!()
                };
                assert_eq!(key, profile);
                assert_eq!(public_key, expected_public);
                assert_eq!(address, expected_address);
                assert_eq!(subject, mudra::claim::neuron_of(&expected_public));
                Ok(())
            })
            .unwrap();
    }
}
