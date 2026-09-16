use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Local secret custody over Cybergraph / BBG")]
pub struct Args {
    /// Vault directory (default: ~/.cyber/vault).
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,
    /// Read secret inputs from a trusted pipe.
    #[arg(long, global = true)]
    pub secrets_stdin: bool,
    /// Reuse a request ID for an exact retry.
    #[arg(long, global = true, value_name = "HEX")]
    pub request: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a vault and a separate recovery factor.
    Init {
        /// New file outside the vault for its recovery factor.
        #[arg(long)]
        recovery_file: PathBuf,
    },
    /// Show the local checkpoint without unlocking.
    Status,
    /// Browse stored entries.
    List {
        /// Continue after the last entry ID in the previous page.
        #[arg(long)]
        after: Option<String>,
        /// Maximum entries in this page.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Import a secret or generate a domain root.
    Add {
        /// Secret type to import or generate.
        #[arg(value_enum)]
        kind: Kind,
        /// Name shown in the vault.
        #[arg(long)]
        label: String,
        /// Service or purpose allowed to use this secret.
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
    /// Remove an entry at its exact version.
    Remove {
        /// Entry ID returned by list.
        id: String,
        /// Exact entry version returned by list.
        #[arg(long)]
        version: u64,
    },
    /// Register an encrypted copy destination.
    ReplicaAdd {
        /// Destination directory for encrypted history.
        #[arg(long)]
        path: PathBuf,
        /// Operator-declared disk or device failure domain.
        #[arg(long)]
        failure_domain: String,
    },
    /// Copy and verify history on two or more replicas.
    Sync,
    /// Reveal a permitted password or PIN on the terminal.
    Show { id: String },
    /// Reserve and display a one-time code.
    Otp { id: String },
    /// Consume and display a recovery code.
    RecoveryCode { id: String },
    /// Derive public neuron credentials inside custody.
    DeriveNeuron {
        /// Spell or domain-root entry ID.
        id: String,
        /// BIP-32 path (default: m/44'/118'/0'/0/0).
        #[arg(long, conflicts_with = "domain")]
        path: Option<String>,
        /// Derive from a domain root for this domain.
        #[arg(long)]
        domain: Option<String>,
        /// Address prefix.
        #[arg(long, default_value = "bostrom")]
        hrp: String,
    },
    /// Sign a native neuron action inside custody.
    Sign {
        /// Spell or domain-root entry ID.
        id: String,
        /// Expected native neuron ID (32-byte hex).
        #[arg(long)]
        subject: String,
        /// Canonical action commitment (32-byte hex), authorized by this operator.
        #[arg(long)]
        statement: String,
        /// BIP-32 path (default: m/44'/118'/0'/0/0).
        #[arg(long, conflicts_with = "domain")]
        path: Option<String>,
        /// Derive from a domain root for this domain.
        #[arg(long)]
        domain: Option<String>,
        /// Address prefix; the NSIG1 signature domain stays fixed.
        #[arg(long, default_value = "bostrom")]
        hrp: String,
    },
    /// Save a public checkpoint for independent retention.
    Checkpoint {
        /// New file for the independently retained checkpoint.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a restore and browse entries read-only.
    Recover {
        /// Directory containing the encrypted copy.
        #[arg(long)]
        database: PathBuf,
        /// Independently retained checkpoint file.
        #[arg(long)]
        checkpoint: PathBuf,
        /// Recovery factor file created by init.
        #[arg(long)]
        recovery_file: PathBuf,
        /// Continue after the last entry ID in the previous page.
        #[arg(long)]
        after: Option<String>,
        /// Maximum entries in this page.
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
