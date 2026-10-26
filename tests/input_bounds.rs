use vault::*;
use zeroize::Zeroizing;

#[test]
fn malformed_or_oversized_secret_inputs_reject_without_echoing_content() {
    assert!(SecretInput::password(Zeroizing::new(vec![])).is_err());
    assert!(SecretInput::password(Zeroizing::new(vec![b'x'; MAX_SECRET_BYTES + 1])).is_err());
    assert!(SecretInput::pin(Zeroizing::new(vec![b'x'; 129])).is_err());
    assert!(SecretInput::totp(Zeroizing::new(vec![1; 10]), OtpAlgorithm::Sha1, 6, 30).is_err());
    assert!(SecretInput::totp(Zeroizing::new(vec![1; 20]), OtpAlgorithm::Sha1, 10, 30).is_err());
    assert!(SecretInput::totp(Zeroizing::new(vec![1; 20]), OtpAlgorithm::Sha1, 6, 0).is_err());
    assert!(
        SecretInput::recovery_codes(vec![
            Zeroizing::new(b"same".to_vec()),
            Zeroizing::new(b"same".to_vec())
        ])
        .is_err()
    );
    assert!(
        SecretInput::recovery_codes((0..65).map(|n| Zeroizing::new(vec![n])).collect()).is_err()
    );
    let error = SecretInput::spell("synthetic-private-string-not-a-spell", "").unwrap_err();
    assert!(!error.to_string().contains("synthetic-private-string"));
    let input =
        SecretInput::password(Zeroizing::new(b"synthetic-private-string".to_vec())).unwrap();
    assert!(!format!("{input:?}").contains("synthetic-private-string"));
}
