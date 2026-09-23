use std::fmt;

pub const MAX_SECRET_BYTES: usize = 16 * 1024;
pub const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;
/// Maximum rows per read, not a limit on the total history/catalog.
pub const MAX_PAGE_SIZE: usize = 4096;
pub const HISTORY_PAGE_SIZE: usize = 256;

macro_rules! id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);
        impl $name {
            pub fn random() -> Result<Self> {
                let mut bytes = [0; $len];
                getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
                Ok(Self(bytes))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
        }
    };
}
id!(VaultId, 32);
id!(SecretRef, 16);
id!(RequestId, 32);
id!(ActorId, 32);
id!(PolicyRef, 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    pub index: u64,
    pub commit: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub actor: ActorId,
    pub policy: PolicyRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Denied,
    Locked,
    ReadOnly,
    Frozen,
    NotFound,
    AlreadyExists,
    Conflict,
    StaleAnchor,
    Corrupt,
    Authentication,
    Unsupported,
    Limit,
    Entropy,
    Storage,
    CommitUnknown,
    ReplicationRequired,
    InvalidInput,
    Exhausted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vault: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_are_the_declared_length_and_not_all_zero() {
        let a = VaultId::random().unwrap();
        assert_eq!(a.0.len(), 32);
        assert_ne!(a.0, [0; 32]);
        let b = SecretRef::random().unwrap();
        assert_eq!(b.0.len(), 16);
        assert_ne!(b.0, [0; 16]);
    }

    #[test]
    fn two_random_ids_are_not_equal() {
        assert_ne!(VaultId::random().unwrap(), VaultId::random().unwrap());
        assert_ne!(RequestId::random().unwrap(), RequestId::random().unwrap());
        assert_ne!(ActorId::random().unwrap(), ActorId::random().unwrap());
        assert_ne!(PolicyRef::random().unwrap(), PolicyRef::random().unwrap());
    }

    #[test]
    fn debug_prints_the_type_name_and_lowercase_hex_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0x00;
        bytes[31] = 0xff;
        assert_eq!(
            format!("{:?}", VaultId(bytes)),
            format!("VaultId(ab00{}ff)", "00".repeat(29))
        );
        assert_eq!(format!("{:?}", SecretRef([0x12; 16])), "SecretRef(12121212121212121212121212121212)");
    }

    #[test]
    fn ids_order_and_hash_by_their_underlying_bytes() {
        assert!(SecretRef([1; 16]) < SecretRef([2; 16]));
        assert_eq!(SecretRef([1; 16]).cmp(&SecretRef([1; 16])), std::cmp::Ordering::Equal);
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ActorId([1; 32]));
        assert!(set.contains(&ActorId([1; 32])));
        assert!(!set.contains(&ActorId([2; 32])));
    }

    #[test]
    fn error_display_is_prefixed_with_vault_and_matches_the_debug_variant() {
        for e in [
            Error::Denied,
            Error::StaleAnchor,
            Error::ReplicationRequired,
            Error::Exhausted,
        ] {
            assert_eq!(format!("{e}"), format!("vault: {e:?}"));
        }
    }
}
