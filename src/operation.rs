use crate::{
    Context, EntryInfo, Error, RequestId, Result, Revision, SecretRef, VaultId,
    codec::{Decoder, Encoder},
};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Derivation {
    Cosmos { path: String, hrp: String },
    Domain { domain: String, hrp: String },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeuronKeyRef {
    pub root: SecretRef,
    pub derivation: Derivation,
}

/// Exact native NSIG1 operation; the host authorizes the action behind its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub key: NeuronKeyRef,
    pub subject: [u8; 32],
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Reveal {
        secret: SecretRef,
        surface: String,
    },
    Deliver {
        secret: SecretRef,
        destination: String,
    },
    Otp {
        secret: SecretRef,
    },
    RecoveryCode {
        secret: SecretRef,
    },
    DeriveNeuron(NeuronKeyRef),
    Sign(SignRequest),
}
impl Operation {
    pub fn secret(&self) -> SecretRef {
        match self {
            Self::Reveal { secret, .. }
            | Self::Deliver { secret, .. }
            | Self::Otp { secret }
            | Self::RecoveryCode { secret } => *secret,
            Self::DeriveNeuron(k) => k.root,
            Self::Sign(request) => request.key.root,
        }
    }
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new();
        match self {
            Self::Reveal { secret, surface } => {
                bounded(surface, 256)?;
                e.byte(1);
                e.fixed(&secret.0);
                e.text(surface)?;
            }
            Self::Deliver {
                secret,
                destination,
            } => {
                bounded(destination, 1024)?;
                e.byte(2);
                e.fixed(&secret.0);
                e.text(destination)?;
            }
            Self::Otp { secret } => {
                e.byte(3);
                e.fixed(&secret.0);
            }
            Self::RecoveryCode { secret } => {
                e.byte(4);
                e.fixed(&secret.0);
            }
            Self::DeriveNeuron(_) | Self::Sign(_) => {
                let (tag, k) = match self {
                    Self::DeriveNeuron(k) => (5, k),
                    Self::Sign(request) => (6, &request.key),
                    _ => unreachable!(),
                };
                e.byte(tag);
                e.fixed(&k.root.0);
                match &k.derivation {
                    Derivation::Cosmos { path, hrp } => {
                        bounded(path, 256)?;
                        bounded(hrp, 83)?;
                        e.byte(1);
                        e.text(path)?;
                        e.text(hrp)?;
                    }
                    Derivation::Domain { domain, hrp } => {
                        bounded(domain, 253)?;
                        bounded(hrp, 83)?;
                        if !domain.is_ascii() || domain.contains('\0') {
                            return Err(Error::InvalidInput);
                        }
                        e.byte(2);
                        e.text(domain)?;
                        e.text(hrp)?;
                    }
                }
                if let Self::Sign(request) = self {
                    e.fixed(&request.subject);
                    e.fixed(&request.statement);
                }
            }
        }
        Ok(e.0)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes)?;
        let tag = d.byte()?;
        let secret = SecretRef(d.array()?);
        let op = match tag {
            1 => Self::Reveal {
                secret,
                surface: d.text(256)?,
            },
            2 => Self::Deliver {
                secret,
                destination: d.text(1024)?,
            },
            3 => Self::Otp { secret },
            4 => Self::RecoveryCode { secret },
            5 | 6 => {
                let key = NeuronKeyRef {
                    root: secret,
                    derivation: match d.byte()? {
                        1 => Derivation::Cosmos {
                            path: d.text(256)?,
                            hrp: d.text(83)?,
                        },
                        2 => Derivation::Domain {
                            domain: d.text(253)?,
                            hrp: d.text(83)?,
                        },
                        _ => return Err(Error::Unsupported),
                    },
                };
                if tag == 5 {
                    Self::DeriveNeuron(key)
                } else {
                    Self::Sign(SignRequest {
                        key,
                        subject: d.array()?,
                        statement: d.array()?,
                    })
                }
            }
            _ => return Err(Error::Unsupported),
        };
        d.finish()?;
        op.encode()?;
        Ok(op)
    }
}
fn bounded(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum IntentKind {
    Create,
    Inspect,
    Put {
        entry: EntryInfo,
        expected_version: Option<u64>,
    },
    Delete {
        secret: SecretRef,
        expected_version: u64,
    },
    Prepare {
        entry: EntryInfo,
        operation: Operation,
    },
    Release {
        entry: EntryInfo,
        operation: Operation,
    },
}
#[derive(Debug)]
pub struct Intent {
    pub vault: VaultId,
    pub request: RequestId,
    pub context: Context,
    pub kind: IntentKind,
    /// Keyed binding to the exact input; never a public password hash.
    pub binding: [u8; 32],
}
/// Trusted-host port. Implementations authenticate Context and hold current
/// authorization through the callback. The callback's clock is supplied by Ward.
/// This crate intentionally supplies no permissive production implementation.
pub trait Ward {
    fn with_authorization<T>(
        &self,
        intent: &Intent,
        action: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T>;
}

#[derive(Clone, Debug)]
pub struct PendingUse {
    pub(crate) vault: VaultId,
    pub(crate) request: RequestId,
    pub(crate) revision: Revision,
    pub(crate) context: Context,
}
impl PendingUse {
    pub fn revision(&self) -> Revision {
        self.revision
    }
    pub fn request(&self) -> RequestId {
        self.request
    }
}

pub enum Output {
    Secret(Zeroizing<Vec<u8>>),
    Neuron {
        key: NeuronKeyRef,
        subject: [u8; 32],
        public_key: [u8; 33],
        address: String,
    },
    Signature {
        request: SignRequest,
        evidence: Vec<u8>,
    },
}
impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultOutput([REDACTED])")
    }
}
impl Output {
    pub(crate) fn encode(&self, created_at: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new();
        e.u64(created_at);
        match self {
            Self::Secret(value) => {
                e.byte(1);
                e.bytes(value)?;
            }
            Self::Neuron {
                key,
                subject,
                public_key,
                address,
            } => {
                e.byte(2);
                e.bytes(&Operation::DeriveNeuron(key.clone()).encode()?)?;
                e.fixed(subject);
                e.fixed(public_key);
                e.text(address)?;
            }
            Self::Signature { request, evidence } => {
                if !mudra::neuron::verify_statement(request.subject, request.statement, evidence) {
                    return Err(Error::Corrupt);
                }
                e.byte(3);
                e.bytes(&Operation::Sign(request.clone()).encode()?)?;
                e.fixed(evidence);
            }
        }
        Ok(e.0)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<(u64, Self)> {
        let mut d = Decoder::new(bytes)?;
        let created_at = d.u64()?;
        let output = match d.byte()? {
            1 => Self::Secret(Zeroizing::new(d.bytes(crate::MAX_SECRET_BYTES)?.to_vec())),
            2 => {
                let Operation::DeriveNeuron(key) = Operation::decode(d.bytes(1024)?)? else {
                    return Err(Error::Corrupt);
                };
                Self::Neuron {
                    key,
                    subject: d.array()?,
                    public_key: d.array()?,
                    address: d.text(256)?,
                }
            }
            3 => {
                let Operation::Sign(request) = Operation::decode(d.bytes(1024)?)? else {
                    return Err(Error::Corrupt);
                };
                let evidence = d.array::<102>()?.to_vec();
                if !mudra::neuron::verify_statement(request.subject, request.statement, &evidence) {
                    return Err(Error::Corrupt);
                }
                Self::Signature { request, evidence }
            }
            _ => return Err(Error::Corrupt),
        };
        d.finish()?;
        Ok((created_at, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_wire_has_fixed_tags_and_rejects_truncation_trailing_and_changed_evidence() {
        let key = mudra::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let subject = mudra::claim::neuron_of(&mudra::cosmos::compressed(key.verifying_key()));
        let request = SignRequest {
            key: NeuronKeyRef {
                root: SecretRef([1; 16]),
                derivation: Derivation::Domain {
                    domain: "test".into(),
                    hrp: "x".into(),
                },
            },
            subject,
            statement: [3; 32],
        };
        let op = Operation::Sign(request.clone());
        let mut expected = vec![6];
        expected.extend([1; 16]);
        expected.push(2);
        expected.extend(4u32.to_le_bytes());
        expected.extend(b"test");
        expected.extend(1u32.to_le_bytes());
        expected.extend(b"x");
        expected.extend(subject);
        expected.extend([3; 32]);
        assert_eq!(op.encode().unwrap().as_slice(), expected);
        assert_eq!(Operation::decode(&expected).unwrap(), op);
        for n in 0..expected.len() {
            assert!(Operation::decode(&expected[..n]).is_err());
        }
        expected.push(0);
        assert!(Operation::decode(&expected).is_err());
        let output = Output::Signature {
            evidence: mudra::neuron::sign(&key, subject, [3; 32]).unwrap(),
            request,
        };
        let bytes = output.encode(59).unwrap();
        assert_eq!(&bytes[..8], &59u64.to_le_bytes());
        assert_eq!(bytes[8], 3);
        assert!(matches!(
            Output::decode(&bytes),
            Ok((59, Output::Signature { .. }))
        ));
        for n in 0..bytes.len() {
            assert!(Output::decode(&bytes[..n]).is_err());
        }
        let mut changed = bytes.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(Output::decode(&changed).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Output::decode(&trailing).is_err());
    }
}
