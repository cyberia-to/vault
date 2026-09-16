#![forbid(unsafe_code)]

#[path = "vault/args.rs"]
mod args;
#[path = "vault/commands.rs"]
mod commands;
#[path = "vault/host.rs"]
mod host;
#[path = "vault/io.rs"]
mod io;
#[path = "vault/owner.rs"]
mod owner;

use clap::Parser;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    let mut argv: Vec<_> = std::env::args_os().collect();
    if argv.len() == 1 {
        argv.push("--help".into());
    }
    if let Err(error) = commands::run(args::Args::parse_from(argv)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
