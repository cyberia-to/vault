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
    Spell = 7,
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
    pub fn spell(words: &str, passphrase: &str) -> Result<Self> {
        if words.len() > 1024 || passphrase.len() > 1024 {
            return Err(Error::Limit);
        }
        let spell = Zeroizing::new(
            mudra::spell::derive(words, passphrase).map_err(|_| Error::InvalidInput)?,
        );
        Self::bytes(SecretKind::Spell, Zeroizing::new(spell.to_vec()))
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
            Payload::Bytes(SecretKind::Spell, v) => v.len() == 64,
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
            7 => SecretKind::Spell,
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
