use crate::{
    Derivation, Entry, Error, Operation, OtpAlgorithm, Output, Result, SecretKind, record::Payload,
};
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

pub(crate) fn perform(entry: &mut Entry, operation: &Operation, now: u64) -> Result<Output> {
    match operation {
        Operation::Reveal { .. } => {
            if !entry.info.revealable {
                return Err(Error::Denied);
            }
            match &entry.input.0 {
                Payload::Bytes(SecretKind::Password | SecretKind::Pin, bytes) => {
                    Ok(Output::Secret(bytes.clone()))
                }
                _ => Err(Error::Denied),
            }
        }
        Operation::Deliver { destination, .. } => {
            if *destination != entry.info.scope {
                return Err(Error::Denied);
            }
            match &entry.input.0 {
                Payload::Bytes(
                    SecretKind::Password | SecretKind::Pin | SecretKind::Token,
                    bytes,
                ) => Ok(Output::Secret(bytes.clone())),
                _ => Err(Error::Denied),
            }
        }
        Operation::Otp { .. } => {
            let Payload::Otp {
                key,
                algorithm,
                digits,
                counter,
                period,
            } = &mut entry.input.0
            else {
                return Err(Error::Denied);
            };
            let value = if *period == 0 {
                *counter
            } else {
                now / u64::from(*period)
            };
            let code = otp(key, *algorithm, *digits, value)?;
            if *period == 0 {
                *counter = counter.checked_add(1).ok_or(Error::Exhausted)?;
            }
            Ok(Output::Secret(code))
        }
        Operation::RecoveryCode { .. } => {
            let Payload::Codes { values, used } = &mut entry.input.0 else {
                return Err(Error::Denied);
            };
            let i = (0..values.len())
                .find(|i| *used & (1u64 << i) == 0)
                .ok_or(Error::Exhausted)?;
            *used |= 1u64 << i;
            Ok(Output::Secret(values[i].clone()))
        }
        Operation::DeriveNeuron(key) => {
            let Payload::Bytes(kind, bytes) = &entry.input.0 else {
                return Err(Error::Denied);
            };
            let (public_key, address) = match (&key.derivation, kind) {
                (Derivation::Cosmos { path, hrp }, SecretKind::Spell) => {
                    let spell = Zeroizing::new(
                        <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt)?,
                    );
                    let signing =
                        mudra::spell::signing_key(&spell, path).map_err(|_| Error::InvalidInput)?;
                    let public = mudra::cosmos::compressed(signing.verifying_key());
                    let address =
                        mudra::cosmos::address(&public, hrp).map_err(|_| Error::InvalidInput)?;
                    (public, address)
                }
                (Derivation::Domain { domain, hrp }, SecretKind::DomainRoot) => {
                    let entropy = Zeroizing::new(
                        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt)?,
                    );
                    let derived = mudra::domain::DomainKey::derive(&entropy, domain, hrp)
                        .map_err(|_| Error::InvalidInput)?;
                    (derived.pubkey, derived.bech32)
                }
                _ => return Err(Error::Denied),
            };
            Ok(Output::Neuron {
                key: key.clone(),
                subject: mudra::claim::neuron_of(&public_key),
                public_key,
                address,
            })
        }
    }
}

pub(crate) fn otp(
    key: &[u8],
    algorithm: OtpAlgorithm,
    digits: u8,
    counter: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = counter.to_be_bytes();
    let digest = match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<sha1::Sha1>::new_from_slice(key).map_err(|_| Error::InvalidInput)?;
            mac.update(&bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        OtpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| Error::InvalidInput)?;
            mac.update(&bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::Corrupt)?,
    ) & 0x7fff_ffff;
    let mut code = Zeroizing::new(vec![b'0'; usize::from(digits)]);
    let mut value = value % 10u32.pow(u32::from(digits));
    for ch in code.iter_mut().rev() {
        *ch += (value % 10) as u8;
        value /= 10;
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hotp_matches_rfc4226_independent_vectors() {
        let vectors = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, expected) in vectors.iter().enumerate() {
            assert_eq!(
                otp(
                    b"12345678901234567890",
                    OtpAlgorithm::Sha1,
                    6,
                    counter as u64
                )
                .unwrap()
                .as_slice(),
                expected.as_bytes()
            );
        }
    }
    #[test]
    fn totp_matches_rfc6238_sha1_and_sha256_vectors() {
        let times = [
            59,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
            20000000000,
        ];
        let sha1 = [
            "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
        ];
        let sha256 = [
            "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
        ];
        for (i, t) in times.iter().enumerate() {
            assert_eq!(
                otp(b"12345678901234567890", OtpAlgorithm::Sha1, 8, t / 30)
                    .unwrap()
                    .as_slice(),
                sha1[i].as_bytes()
            );
            assert_eq!(
                otp(
                    b"12345678901234567890123456789012",
                    OtpAlgorithm::Sha256,
                    8,
                    t / 30
                )
                .unwrap()
                .as_slice(),
                sha256[i].as_bytes()
            );
        }
    }
}
