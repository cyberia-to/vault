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
