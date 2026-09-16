#![forbid(unsafe_code)]

#[path = "vault/args.rs"]
mod args;
#[path = "vault/commands.rs"]
mod commands;
#[path = "vault/help.rs"]
mod help;
#[path = "vault/host.rs"]
mod host;
#[path = "vault/io.rs"]
mod io;
#[path = "vault/owner.rs"]
mod owner;

use clap::{CommandFactory, FromArgMatches};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    let mut argv: Vec<_> = std::env::args_os().collect();
    if argv.len() == 1 {
        argv.push("--help".into());
    }
    let matches = help::command(args::Args::command()).get_matches_from(argv);
    let args = args::Args::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    if let Err(error) = commands::run(args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
