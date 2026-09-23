use crate::{
    Error, MAX_SECRET_BYTES, PolicyRef, Result, SecretRef,
    codec::{Decoder, Encoder},
};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecretKind {
    Password = 1,
    Pin = 2,
    Token = 3,
    Totp = 4,
    Hotp = 5,
    RecoveryCodes = 6,
    Bip39Seed = 7,
    DomainRoot = 8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OtpAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
}

#[derive(Clone)]
pub(crate) enum Payload {
    Bytes(SecretKind, Zeroizing<Vec<u8>>),
    Otp {
        key: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        counter: u64,
        period: u32,
    },
    Codes {
        values: Vec<Zeroizing<Vec<u8>>>,
        used: u64,
    },
}
/// Owned protected input. No serialization, payload getter or plaintext Debug.
pub struct SecretInput(pub(crate) Payload);
impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}
impl SecretInput {
    pub fn password(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        Self::bytes(SecretKind::Password, bytes)
    }
    pub fn pin(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        Self::bytes(SecretKind::Pin, bytes)
    }
    pub fn token(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        Self::bytes(SecretKind::Token, bytes)
    }
    pub fn domain_root(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        Self::bytes(SecretKind::DomainRoot, Zeroizing::new(bytes.to_vec()))
    }
    pub fn generate_domain_root() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::getrandom(bytes.as_mut()).map_err(|_| Error::Entropy)?;
        Self::domain_root(bytes)
    }
    pub fn mnemonic(words: &str, passphrase: &str) -> Result<Self> {
        if words.len() > 1024 || passphrase.len() > 1024 {
            return Err(Error::Limit);
        }
        let seed =
            Zeroizing::new(mudra::seed::seed(words, passphrase).map_err(|_| Error::InvalidInput)?);
        Self::bytes(SecretKind::Bip39Seed, Zeroizing::new(seed.to_vec()))
    }
    pub fn totp(
        key: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        period: u32,
    ) -> Result<Self> {
        if !(15..=120).contains(&period) {
            return Err(Error::InvalidInput);
        }
        Self::otp(key, algorithm, digits, 0, period)
    }
    pub fn hotp(
        key: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        counter: u64,
    ) -> Result<Self> {
        Self::otp(key, algorithm, digits, counter, 0)
    }
    pub fn recovery_codes(values: Vec<Zeroizing<Vec<u8>>>) -> Result<Self> {
        let input = Self(Payload::Codes { values, used: 0 });
        input.validate()?;
        Ok(input)
    }
    fn bytes(kind: SecretKind, bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let input = Self(Payload::Bytes(kind, bytes));
        input.validate()?;
        Ok(input)
    }
    fn otp(
        key: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        counter: u64,
        period: u32,
    ) -> Result<Self> {
        let input = Self(Payload::Otp {
            key,
            algorithm,
            digits,
            counter,
            period,
        });
        input.validate()?;
        Ok(input)
    }
    pub fn kind(&self) -> SecretKind {
        match &self.0 {
            Payload::Bytes(kind, _) => *kind,
            Payload::Otp { period: 0, .. } => SecretKind::Hotp,
            Payload::Otp { .. } => SecretKind::Totp,
            Payload::Codes { .. } => SecretKind::RecoveryCodes,
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let valid = match &self.0 {
            Payload::Bytes(SecretKind::Password | SecretKind::Token, v) => {
                !v.is_empty() && v.len() <= MAX_SECRET_BYTES
            }
            Payload::Bytes(SecretKind::Pin, v) => !v.is_empty() && v.len() <= 128,
            Payload::Bytes(SecretKind::DomainRoot, v) => v.len() == 32,
            Payload::Bytes(SecretKind::Bip39Seed, v) => v.len() == 64,
            Payload::Bytes(_, _) => false,
            Payload::Otp {
                key,
                digits,
                period,
                counter,
                ..
            } => {
                (20..=64).contains(&key.len())
                    && [6, 8].contains(digits)
                    && (*period == 0 || ((15..=120).contains(period) && *counter == 0))
            }
            Payload::Codes { values, used } => {
                !values.is_empty()
                    && values.len() <= 64
                    && values.iter().all(|v| !v.is_empty() && v.len() <= 256)
                    && values
                        .iter()
                        .enumerate()
                        .all(|(i, v)| !values[..i].contains(v))
                    && (values.len() == 64 || *used >> values.len() == 0)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
    pub(crate) fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.byte(self.kind() as u8);
        match &self.0 {
            Payload::Bytes(_, v) => e.bytes(v)?,
            Payload::Otp {
                key,
                algorithm,
                digits,
                counter,
                period,
            } => {
                e.bytes(key)?;
                e.byte(*algorithm as u8);
                e.byte(*digits);
                e.u64(*counter);
                e.u32(*period);
            }
            Payload::Codes { values, used } => {
                e.u32(values.len() as u32);
                for v in values {
                    e.bytes(v)?;
                }
                e.u64(*used);
            }
        }
        Ok(())
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let kind = match d.byte()? {
            1 => SecretKind::Password,
            2 => SecretKind::Pin,
            3 => SecretKind::Token,
            4 => SecretKind::Totp,
            5 => SecretKind::Hotp,
            6 => SecretKind::RecoveryCodes,
            7 => SecretKind::Bip39Seed,
            8 => SecretKind::DomainRoot,
            _ => return Err(Error::Unsupported),
        };
        let payload = match kind {
            SecretKind::Totp | SecretKind::Hotp => {
                let key = Zeroizing::new(d.bytes(64)?.to_vec());
                let algorithm = match d.byte()? {
                    1 => OtpAlgorithm::Sha1,
                    2 => OtpAlgorithm::Sha256,
                    _ => return Err(Error::Unsupported),
                };
                let digits = d.byte()?;
                let counter = d.u64()?;
                let period = d.u32()?;
                if (kind == SecretKind::Hotp) != (period == 0) {
                    return Err(Error::Corrupt);
                }
                Payload::Otp {
                    key,
                    algorithm,
                    digits,
                    counter,
                    period,
                }
            }
            SecretKind::RecoveryCodes => {
                let count = d.u32()? as usize;
                if count > 64 {
                    return Err(Error::Limit);
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(Zeroizing::new(d.bytes(256)?.to_vec()));
                }
                Payload::Codes {
                    values,
                    used: d.u64()?,
                }
            }
            _ => Payload::Bytes(kind, Zeroizing::new(d.bytes(MAX_SECRET_BYTES)?.to_vec())),
        };
        let input = Self(payload);
        input.validate().map_err(|_| Error::Corrupt)?;
        Ok(input)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EntryInfo {
    pub id: SecretRef,
    pub kind: SecretKind,
    pub label: String,
    pub scope: String,
    pub policy: PolicyRef,
    pub version: u64,
    pub revealable: bool,
}
impl fmt::Debug for EntryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryInfo")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
pub struct Entry {
    pub(crate) info: EntryInfo,
    pub(crate) input: SecretInput,
}
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Entry([REDACTED])")
    }
}
impl Entry {
    pub fn new(
        id: SecretRef,
        label: String,
        scope: String,
        policy: PolicyRef,
        revealable: bool,
        input: SecretInput,
    ) -> Result<Self> {
        let entry = Self {
            info: EntryInfo {
                id,
                kind: input.kind(),
                label,
                scope,
                policy,
                version: 0,
                revealable,
            },
            input,
        };
        entry.validate()?;
        Ok(entry)
    }
    pub fn info(&self) -> &EntryInfo {
        &self.info
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.input.validate()?;
        if self.info.label.is_empty()
            || self.info.label.len() > 256
            || self.info.scope.is_empty()
            || self.info.scope.len() > 1024
        {
            return Err(Error::InvalidInput);
        }
        if self.info.revealable && !matches!(self.info.kind, SecretKind::Password | SecretKind::Pin)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    pub(crate) fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.fixed(&self.info.id.0);
        e.text(&self.info.label)?;
        e.text(&self.info.scope)?;
        e.fixed(&self.info.policy.0);
        e.u64(self.info.version);
        e.byte(u8::from(self.info.revealable));
        self.input.encode(e)
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let id = SecretRef(d.array()?);
        let label = d.text(256)?;
        let scope = d.text(1024)?;
        let policy = PolicyRef(d.array()?);
        let version = d.u64()?;
        let revealable = match d.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Corrupt),
        };
        let input = SecretInput::decode(d)?;
        let mut entry =
            Self::new(id, label, scope, policy, revealable, input).map_err(|_| Error::Corrupt)?;
        entry.info.version = version;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![7; n])
    }
    fn otp_key() -> Zeroizing<Vec<u8>> {
        bytes(32)
    }
    fn round_trip(input: SecretInput) -> SecretInput {
        let mut e = Encoder::new();
        input.encode(&mut e).unwrap();
        let mut d = Decoder::new(&e.0).unwrap();
        let decoded = SecretInput::decode(&mut d).unwrap();
        d.finish().unwrap();
        decoded
    }
    fn entry(input: SecretInput, revealable: bool) -> Result<Entry> {
        Entry::new(
            SecretRef([1; 16]),
            "label".into(),
            "scope".into(),
            PolicyRef([2; 32]),
            revealable,
            input,
        )
    }

    #[test]
    fn password_pin_token_validate_length_bounds() {
        assert!(SecretInput::password(bytes(0)).is_err());
        assert!(SecretInput::password(bytes(1)).is_ok());
        assert!(SecretInput::password(bytes(MAX_SECRET_BYTES)).is_ok());
        assert!(SecretInput::password(bytes(MAX_SECRET_BYTES + 1)).is_err());

        assert!(SecretInput::token(bytes(0)).is_err());
        assert!(SecretInput::token(bytes(MAX_SECRET_BYTES)).is_ok());
        assert!(SecretInput::token(bytes(MAX_SECRET_BYTES + 1)).is_err());

        assert!(SecretInput::pin(bytes(0)).is_err());
        assert!(SecretInput::pin(bytes(128)).is_ok());
        assert!(SecretInput::pin(bytes(129)).is_err());
    }

    #[test]
    fn domain_root_is_generated_at_the_right_length_and_kind() {
        let input = SecretInput::generate_domain_root().unwrap();
        assert_eq!(input.kind(), SecretKind::DomainRoot);
        assert!(SecretInput::domain_root(Zeroizing::new([0; 32])).is_ok());
    }

    #[test]
    fn mnemonic_rejects_oversized_words_and_passphrase() {
        let long = "x".repeat(1025);
        assert!(matches!(
            SecretInput::mnemonic(&long, ""),
            Err(Error::Limit)
        ));
        assert!(matches!(
            SecretInput::mnemonic("", &long),
            Err(Error::Limit)
        ));
    }

    #[test]
    fn totp_rejects_period_outside_15_to_120() {
        assert!(SecretInput::totp(otp_key(), OtpAlgorithm::Sha1, 6, 14).is_err());
        assert!(SecretInput::totp(otp_key(), OtpAlgorithm::Sha1, 6, 15).is_ok());
        assert!(SecretInput::totp(otp_key(), OtpAlgorithm::Sha1, 6, 120).is_ok());
        assert!(SecretInput::totp(otp_key(), OtpAlgorithm::Sha1, 6, 121).is_err());
    }

    #[test]
    fn otp_validate_rejects_out_of_range_key_length_and_digits() {
        assert!(SecretInput::hotp(bytes(19), OtpAlgorithm::Sha1, 6, 0).is_err());
        assert!(SecretInput::hotp(bytes(20), OtpAlgorithm::Sha1, 6, 0).is_ok());
        assert!(SecretInput::hotp(bytes(64), OtpAlgorithm::Sha1, 6, 0).is_ok());
        assert!(SecretInput::hotp(bytes(65), OtpAlgorithm::Sha1, 6, 0).is_err());
        assert!(SecretInput::hotp(otp_key(), OtpAlgorithm::Sha1, 7, 0).is_err());
        assert!(SecretInput::hotp(otp_key(), OtpAlgorithm::Sha1, 8, 0).is_ok());
    }

    #[test]
    fn kind_reports_hotp_when_period_is_zero_and_totp_otherwise() {
        let hotp = SecretInput::hotp(otp_key(), OtpAlgorithm::Sha1, 6, 42).unwrap();
        assert_eq!(hotp.kind(), SecretKind::Hotp);
        let totp = SecretInput::totp(otp_key(), OtpAlgorithm::Sha256, 6, 30).unwrap();
        assert_eq!(totp.kind(), SecretKind::Totp);
    }

    #[test]
    fn recovery_codes_validate_boundaries() {
        assert!(matches!(
            SecretInput::recovery_codes(vec![]),
            Err(Error::InvalidInput)
        ));
        assert!(SecretInput::recovery_codes(vec![bytes(8)]).is_ok());
        assert!(matches!(
            SecretInput::recovery_codes(vec![bytes(0)]),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            SecretInput::recovery_codes(vec![bytes(257)]),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            SecretInput::recovery_codes(vec![bytes(8), bytes(8)]),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            SecretInput::recovery_codes(vec![bytes(1); 65]),
            Err(Error::InvalidInput)
        ));
        let sixty_four: Vec<_> = (0..64).map(|i| Zeroizing::new(vec![i as u8])).collect();
        assert!(SecretInput::recovery_codes(sixty_four).is_ok());
    }

    #[test]
    fn recovery_codes_round_trips_and_preserves_used() {
        let values = vec![bytes(4), bytes(5)];
        let input = SecretInput::recovery_codes(values).unwrap();
        let decoded = round_trip(input);
        assert_eq!(decoded.kind(), SecretKind::RecoveryCodes);
        match decoded.0 {
            Payload::Codes { values, used } => {
                assert_eq!(values.len(), 2);
                assert_eq!(used, 0);
            }
            _ => panic!("expected Codes payload"),
        }
    }

    #[test]
    fn every_secret_kind_round_trips_through_encode_decode() {
        for input in [
            SecretInput::password(bytes(4)).unwrap(),
            SecretInput::pin(bytes(4)).unwrap(),
            SecretInput::token(bytes(4)).unwrap(),
            SecretInput::generate_domain_root().unwrap(),
            SecretInput::totp(otp_key(), OtpAlgorithm::Sha256, 8, 60).unwrap(),
            SecretInput::hotp(otp_key(), OtpAlgorithm::Sha1, 6, 9).unwrap(),
        ] {
            let kind = input.kind();
            let decoded = round_trip(input);
            assert_eq!(decoded.kind(), kind);
        }
    }

    #[test]
    fn decode_rejects_an_unknown_kind_byte() {
        let mut e = Encoder::new();
        e.byte(0);
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(
            SecretInput::decode(&mut d),
            Err(Error::Unsupported)
        ));

        let mut e = Encoder::new();
        e.byte(9);
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(
            SecretInput::decode(&mut d),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_otp_algorithm_byte() {
        let mut e = Encoder::new();
        e.byte(SecretKind::Totp as u8);
        e.bytes(&otp_key()).unwrap();
        e.byte(3); // neither Sha1 (1) nor Sha256 (2)
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(
            SecretInput::decode(&mut d),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn decode_rejects_a_kind_period_mismatch() {
        // kind byte says Totp but the encoded period is 0 (Hotp's shape).
        let mut e = Encoder::new();
        e.byte(SecretKind::Totp as u8);
        e.bytes(&otp_key()).unwrap();
        e.byte(OtpAlgorithm::Sha1 as u8);
        e.byte(6);
        e.u64(0);
        e.u32(0);
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(SecretInput::decode(&mut d), Err(Error::Corrupt)));

        // kind byte says Hotp but the encoded period is non-zero (Totp's shape).
        let mut e = Encoder::new();
        e.byte(SecretKind::Hotp as u8);
        e.bytes(&otp_key()).unwrap();
        e.byte(OtpAlgorithm::Sha1 as u8);
        e.byte(6);
        e.u64(0);
        e.u32(30);
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(SecretInput::decode(&mut d), Err(Error::Corrupt)));
    }

    #[test]
    fn decode_rejects_a_recovery_codes_count_over_64() {
        let mut e = Encoder::new();
        e.byte(SecretKind::RecoveryCodes as u8);
        e.u32(65);
        let mut d = Decoder::new(&e.0).unwrap();
        assert!(matches!(SecretInput::decode(&mut d), Err(Error::Limit)));
    }

    #[test]
    fn entry_validate_rejects_empty_or_oversized_label_and_scope() {
        let input = || SecretInput::password(bytes(4)).unwrap();
        assert!(
            Entry::new(
                SecretRef([1; 16]),
                String::new(),
                "scope".into(),
                PolicyRef([2; 32]),
                false,
                input(),
            )
            .is_err()
        );
        assert!(
            Entry::new(
                SecretRef([1; 16]),
                "x".repeat(257),
                "scope".into(),
                PolicyRef([2; 32]),
                false,
                input(),
            )
            .is_err()
        );
        assert!(
            Entry::new(
                SecretRef([1; 16]),
                "label".into(),
                String::new(),
                PolicyRef([2; 32]),
                false,
                input(),
            )
            .is_err()
        );
        assert!(
            Entry::new(
                SecretRef([1; 16]),
                "label".into(),
                "x".repeat(1025),
                PolicyRef([2; 32]),
                false,
                input(),
            )
            .is_err()
        );
    }

    #[test]
    fn entry_validate_rejects_revealable_outside_password_and_pin() {
        assert!(entry(SecretInput::password(bytes(4)).unwrap(), true).is_ok());
        assert!(entry(SecretInput::pin(bytes(4)).unwrap(), true).is_ok());
        assert!(matches!(
            entry(SecretInput::token(bytes(4)).unwrap(), true),
            Err(Error::Denied)
        ));
        assert!(entry(SecretInput::token(bytes(4)).unwrap(), false).is_ok());
    }

    #[test]
    fn entry_round_trips_through_encode_decode() {
        let original = entry(SecretInput::password(bytes(4)).unwrap(), true).unwrap();
        let mut e = Encoder::new();
        original.encode(&mut e).unwrap();
        let mut d = Decoder::new(&e.0).unwrap();
        let decoded = Entry::decode(&mut d).unwrap();
        d.finish().unwrap();
        assert_eq!(decoded.info().id, original.info().id);
        assert_eq!(decoded.info().label, original.info().label);
        assert_eq!(decoded.info().scope, original.info().scope);
        assert_eq!(decoded.info().policy, original.info().policy);
        assert_eq!(decoded.info().version, original.info().version);
        assert_eq!(decoded.info().revealable, original.info().revealable);
        assert_eq!(decoded.info().kind, original.info().kind);
    }

    #[test]
    fn entry_decode_rejects_an_invalid_revealable_byte() {
        let original = entry(SecretInput::password(bytes(4)).unwrap(), false).unwrap();
        let mut e = Encoder::new();
        original.encode(&mut e).unwrap();
        let mut bytes = e.0.to_vec();
        // revealable byte sits right after id(16) + label(4+5) + scope(4+5) + policy(32) + version(8).
        let offset = 16 + 4 + 5 + 4 + 5 + 32 + 8;
        assert_eq!(bytes[offset], 0);
        bytes[offset] = 2;
        let mut d = Decoder::new(&bytes).unwrap();
        assert!(matches!(Entry::decode(&mut d), Err(Error::Corrupt)));
    }
}
