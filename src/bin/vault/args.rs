use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Local secret custody over Cybergraph / BBG")]
pub struct Args {
    /// Private host directory (default: ~/.cyber/vault).
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,
    /// Read secret inputs as consecutive lines from a pipe, without echo.
    #[arg(long, global = true)]
    pub secrets_stdin: bool,
    /// Reuse the original 32-byte hex request ID when retrying a mutation/use.
    #[arg(long, global = true)]
    pub request: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a vault; keep the recovery file separately from the host directory.
    Init {
        #[arg(long)]
        recovery_file: PathBuf,
    },
    /// Show the retained local checkpoint without unlocking.
    Status,
    /// List a page of entry metadata after unlocking.
    List {
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Import a secret through hidden prompts, or generate a domain root.
    Add {
        #[arg(value_enum)]
        kind: Kind,
        #[arg(long)]
        label: String,
        #[arg(long)]
        scope: String,
        /// Optional 16-byte hex entry ID for exact retries.
        #[arg(long)]
        id: Option<String>,
        /// Permit explicit terminal reveal (password/PIN only).
        #[arg(long)]
        revealable: bool,
        /// OTP digit count.
        #[arg(long, default_value_t = 6)]
        digits: u8,
        /// TOTP period in seconds.
        #[arg(long, default_value_t = 30)]
        period: u32,
        /// Initial HOTP counter.
        #[arg(long, default_value_t = 0)]
        counter: u64,
        /// OTP hash algorithm.
        #[arg(long, value_enum, default_value_t = Algorithm::Sha1)]
        algorithm: Algorithm,
    },
    /// Delete exactly this entry version.
    Remove {
        id: String,
        #[arg(long)]
        version: u64,
    },
    /// Register a local ciphertext store in a declared failure domain.
    ReplicaAdd {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        failure_domain: String,
    },
    /// Replicate and read back history to at least two registered destinations.
    Sync,
    /// Reveal a permitted password/PIN on the controlling terminal.
    Show { id: String },
    /// Generate an OTP on the controlling terminal after durable reservation.
    Otp { id: String },
    /// Consume one recovery code and deliver it on the controlling terminal.
    RecoveryCode { id: String },
    /// Derive public neuron credentials; root material stays inside custody.
    DeriveNeuron {
        id: String,
        #[arg(long, conflicts_with = "domain")]
        path: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long, default_value = "bostrom")]
        hrp: String,
    },
    /// Export a public checkpoint to a new file for independent retention.
    Checkpoint {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify recovery against an independent checkpoint and list metadata.
    Recover {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        recovery_file: PathBuf,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Kind {
    Password,
    Pin,
    Token,
    Spell,
    DomainRoot,
    Totp,
    Hotp,
    RecoveryCodes,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Algorithm {
    Sha1,
    Sha256,
}
