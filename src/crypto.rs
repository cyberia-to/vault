use crate::{
    Error, MAX_PACKET_BYTES, Result, Revision, VaultId,
    codec::{Decoder, Encoder},
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"CVLT1";
const WRAP_BYTES: usize = 72;

pub(crate) struct Keys(pub Zeroizing<[u8; 32]>);
impl Keys {
    pub fn fingerprint(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .map_err(|_| Error::Authentication)?;
        derive.update(b"vault/request-key/v1");
        let key = Zeroizing::new(<[u8; 32]>::from(derive.finalize().into_bytes()));
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref())
            .map_err(|_| Error::Authentication)?;
        mac.update(b"vault/request/v1");
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub vault: VaultId,
    salt: [u8; 16],
    unlock: [u8; WRAP_BYTES],
    recovery: [u8; WRAP_BYTES],
}
impl Header {
    pub fn create(vault: VaultId, passphrase: &[u8], recovery: &[u8; 32]) -> Result<(Self, Keys)> {
        if !(12..=1024).contains(&passphrase.len()) {
            return Err(Error::InvalidInput);
        }
        let salt = random()?;
        let keys = Keys(Zeroizing::new(random()?));
        let unlock_key = password_key(passphrase, &salt)?;
        let unlock = wrap(&unlock_key, &wrap_aad(vault, &salt, 0), &keys.0)?;
        let recovery = wrap(recovery, &wrap_aad(vault, &salt, 1), &keys.0)?;
        Ok((
            Self {
                vault,
                salt,
                unlock,
                recovery,
            },
            keys,
        ))
    }
    pub fn unlock(&self, password: &[u8]) -> Result<Keys> {
        let key = password_key(password, &self.salt)?;
        unwrap(&key, &wrap_aad(self.vault, &self.salt, 0), &self.unlock)
    }
    pub fn recover(&self, key: &[u8; 32]) -> Result<Keys> {
        unwrap(key, &wrap_aad(self.vault, &self.salt, 1), &self.recovery)
    }
    fn encode(&self, e: &mut Encoder) {
        e.fixed(MAGIC);
        e.fixed(&self.vault.0);
        e.fixed(&self.salt);
        e.fixed(&self.unlock);
        e.fixed(&self.recovery);
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        if d.take(5)? != MAGIC {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            vault: VaultId(d.array()?),
            salt: d.array()?,
            unlock: d.array()?,
            recovery: d.array()?,
        })
    }
}

pub(crate) struct Packet {
    pub header: Header,
    pub request: crate::RequestId,
    pub index: u64,
    pub previous: Option<Revision>,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
impl Packet {
    pub fn seal(
        header: Header,
        keys: &Keys,
        request: crate::RequestId,
        previous: Option<Revision>,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        if plaintext.len() > MAX_PACKET_BYTES - 1024 {
            return Err(Error::Limit);
        }
        let index = match previous {
            Some(r) => r.index.checked_add(1).ok_or(Error::Limit)?,
            None => 0,
        };
        let mut packet = Self {
            header,
            request,
            index,
            previous,
            nonce: random()?,
            ciphertext: Vec::new(),
        };
        let mut buffer = plaintext;
        let cipher = XChaCha20Poly1305::new((&*keys.0).into());
        cipher
            .encrypt_in_place(
                XNonce::from_slice(&packet.nonce),
                &packet.aad(),
                &mut *buffer,
            )
            .map_err(|_| Error::Authentication)?;
        packet.ciphertext = buffer.to_vec();
        Ok(packet)
    }
    fn aad(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        self.header.encode(&mut e);
        e.fixed(&self.request.0);
        e.u64(self.index);
        match self.previous {
            None => e.byte(0),
            Some(r) => {
                e.byte(1);
                e.u64(r.index);
                e.fixed(&r.commit);
            }
        }
        e.0
    }
    pub fn open(&self, keys: &Keys) -> Result<Zeroizing<Vec<u8>>> {
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        XChaCha20Poly1305::new((&*keys.0).into())
            .decrypt_in_place(
                XNonce::from_slice(&self.nonce),
                &self.aad(),
                &mut *plaintext,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(plaintext)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder(self.aad());
        e.fixed(&self.nonce);
        e.bytes(&self.ciphertext)?;
        Ok(e.0.to_vec())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes)?;
        let header = Header::decode(&mut d)?;
        let request = crate::RequestId(d.array()?);
        let index = d.u64()?;
        let previous = match d.byte()? {
            0 if index == 0 => None,
            1 if index > 0 => {
                let r = Revision {
                    index: d.u64()?,
                    commit: d.array()?,
                };
                if r.index.checked_add(1) != Some(index) {
                    return Err(Error::Corrupt);
                }
                Some(r)
            }
            _ => return Err(Error::Corrupt),
        };
        let nonce = d.array()?;
        let ciphertext = d.bytes(MAX_PACKET_BYTES - 512)?.to_vec();
        if ciphertext.len() < 16 {
            return Err(Error::Corrupt);
        }
        d.finish()?;
        Ok(Self {
            header,
            request,
            index,
            previous,
            nonce,
            ciphertext,
        })
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(bytes)
}
fn password_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if password.len() > 1024 {
        return Err(Error::Limit);
    }
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Unsupported)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}
fn wrap_aad(vault: VaultId, salt: &[u8; 16], purpose: u8) -> Vec<u8> {
    let mut v = b"vault/wrap/v1".to_vec();
    v.extend(vault.0);
    v.extend(salt);
    v.push(purpose);
    v
}
fn wrap(key: &[u8; 32], aad: &[u8], data: &[u8; 32]) -> Result<[u8; WRAP_BYTES]> {
    let nonce = random::<24>()?;
    let mut bytes = Zeroizing::new(data.to_vec());
    XChaCha20Poly1305::new(key.into())
        .encrypt_in_place(XNonce::from_slice(&nonce), aad, &mut *bytes)
        .map_err(|_| Error::Authentication)?;
    let mut wrapped = [0; WRAP_BYTES];
    wrapped[..24].copy_from_slice(&nonce);
    wrapped[24..].copy_from_slice(&bytes);
    Ok(wrapped)
}
fn unwrap(key: &[u8; 32], aad: &[u8], wrapped: &[u8; WRAP_BYTES]) -> Result<Keys> {
    let mut bytes = Zeroizing::new(wrapped[24..].to_vec());
    XChaCha20Poly1305::new(key.into())
        .decrypt_in_place(XNonce::from_slice(&wrapped[..24]), aad, &mut *bytes)
        .map_err(|_| Error::Authentication)?;
    Ok(Keys(Zeroizing::new(
        bytes.as_slice().try_into().map_err(|_| Error::Corrupt)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_packet_byte_is_authenticated_or_structurally_rejected() {
        let header = Header {
            vault: VaultId([1; 32]),
            salt: [2; 16],
            unlock: [3; 72],
            recovery: [4; 72],
        };
        let key = Keys(Zeroizing::new([5; 32]));
        let packet = Packet::seal(
            header,
            &key,
            crate::RequestId([6; 32]),
            None,
            Zeroizing::new(b"synthetic authenticated payload".to_vec()),
        )
        .unwrap();
        let bytes = packet.encode().unwrap();
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                Packet::decode(&changed).and_then(|p| p.open(&key)).is_err(),
                "unauthenticated byte {offset}"
            );
        }
        for end in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Packet::decode(&trailing).is_err());
        assert!(packet.open(&Keys(Zeroizing::new([7; 32]))).is_err());
        assert_eq!(
            packet.open(&key).unwrap().as_slice(),
            b"synthetic authenticated payload"
        );
    }
    #[test]
    fn repeated_plaintext_uses_distinct_nonces_and_ciphertexts() {
        let header = Header {
            vault: VaultId([1; 32]),
            salt: [2; 16],
            unlock: [3; 72],
            recovery: [4; 72],
        };
        let key = Keys(Zeroizing::new([5; 32]));
        let seal = || {
            Packet::seal(
                header.clone(),
                &key,
                crate::RequestId([6; 32]),
                None,
                Zeroizing::new(vec![7; 128]),
            )
            .unwrap()
        };
        assert_ne!(seal().encode().unwrap(), seal().encode().unwrap());
    }
}
