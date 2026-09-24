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
    fn random_id_has_the_declared_length_and_is_not_all_zero() {
        let a = VaultId::random().unwrap();
        assert_eq!(a.0.len(), 32);
        assert_ne!(a.0, [0u8; 32], "getrandom returned an all-zero id");
        let b = SecretRef::random().unwrap();
        assert_eq!(b.0.len(), 16);
    }

    #[test]
    fn two_random_ids_differ() {
        // Not a formal randomness proof — a collision would mean getrandom
        // is broken or fixed-seeded, either a real bug worth this test.
        let a = ActorId::random().unwrap();
        let b = ActorId::random().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn id_debug_formats_as_name_and_lowercase_hex() {
        let id = RequestId([0xab; 32]);
        let formatted = format!("{id:?}");
        assert_eq!(formatted, format!("RequestId({})", "ab".repeat(32)));
    }

    #[test]
    fn id_debug_zero_pads_single_digit_bytes() {
        let id = PolicyRef([0x0f; 32]);
        let formatted = format!("{id:?}");
        assert!(
            formatted.contains("0f"),
            "single-digit byte 0x0f must render as \"0f\", not \"f\": {formatted}"
        );
    }

    #[test]
    fn ids_of_the_same_bytes_are_equal_and_ordered_by_bytes() {
        let low = VaultId([0; 32]);
        let mut high_bytes = [0; 32];
        high_bytes[0] = 1;
        let high = VaultId(high_bytes);
        assert_eq!(VaultId([9; 32]), VaultId([9; 32]));
        assert!(low < high);
    }

    #[test]
    fn revision_and_context_are_plain_copyable_equality_types() {
        let r1 = Revision {
            index: 7,
            commit: [1; 32],
        };
        let r2 = r1;
        assert_eq!(r1, r2);
        let mut other = r1;
        other.index = 8;
        assert_ne!(r1, other);

        let c1 = Context {
            actor: ActorId([1; 32]),
            policy: PolicyRef([2; 32]),
        };
        assert_eq!(c1, c1);
    }

    #[test]
    fn error_display_is_the_prefixed_debug_form() {
        assert_eq!(format!("{}", Error::StaleAnchor), "vault: StaleAnchor");
        assert_eq!(format!("{}", Error::Corrupt), "vault: Corrupt");
        assert_eq!(
            format!("{}", Error::ReplicationRequired),
            "vault: ReplicationRequired"
        );
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_std_error<E: std::error::Error>(_: &E) {}
        assert_std_error(&Error::Denied);
    }
}
