#![cfg(feature = "cli")]

use serde_json::Value;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const UNLOCK: &str = "synthetic-unlock-only";

struct Cli {
    dir: TempDir,
    home: PathBuf,
}
impl Cli {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("primary");
        Self { dir, home }
    }
    fn run(&self, args: &[&str], lines: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
            .args(["--home", self.home.to_str().unwrap(), "--secrets-stdin"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in lines {
            writeln!(stdin, "{line}").unwrap();
        }
        drop(stdin);
        child.wait_with_output().unwrap()
    }
    fn ok(&self, args: &[&str], lines: &[&str]) -> Value {
        let output = self.run(args, lines);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for secret in [UNLOCK, WORDS, "synthetic-service-password"] {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        }
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().into()
    }
    fn init(&self) {
        self.ok(
            &["init", "--recovery-file", &self.path("recovery")],
            &[UNLOCK, UNLOCK],
        );
    }
}

#[test]
fn process_restart_spell_derivation_replication_and_recovery() {
    let c = Cli::new();
    c.init();
    let add = c.ok(
        &["add", "spell", "--label", "test root", "--scope", "neuron"],
        &[UNLOCK, WORDS, ""],
    );
    let id = add["id"].as_str().unwrap();
    let list = c.ok(&["list"], &[UNLOCK]);
    assert_eq!(list["entries"][0]["kind"], "Spell");
    assert_eq!(list["entries"][0]["id"], id);
    for (name, domain) in [("a", "test-disk-a"), ("b", "test-disk-b")] {
        c.ok(
            &[
                "replica-add",
                "--path",
                &c.path(name),
                "--failure-domain",
                domain,
            ],
            &[UNLOCK],
        );
    }
    let derived = c.ok(&["derive-neuron", id, "--hrp", "bostrom"], &[UNLOCK]);
    let key = mudra::spell::cosmos_key(WORDS, "").unwrap();
    let public = mudra::cosmos::compressed(key.verifying_key());
    assert_eq!(derived["result"]["public_key"], hex::encode(public));
    assert_eq!(
        derived["result"]["address"],
        mudra::cosmos::address(&public, "bostrom").unwrap()
    );
    c.ok(&["checkpoint", "--out", &c.path("checkpoint")], &[UNLOCK]);
    let before = std::fs::read(c.home.join("host.json")).unwrap();
    let bad = c.run(&["list"], &["wrong-synthetic-password"]);
    assert!(!bad.status.success());
    assert_eq!(std::fs::read(c.home.join("host.json")).unwrap(), before);
    std::fs::remove_dir_all(&c.home).unwrap();
    let recovered = c.ok(
        &[
            "recover",
            "--database",
            &c.path("b"),
            "--checkpoint",
            &c.path("checkpoint"),
            "--recovery-file",
            &c.path("recovery"),
        ],
        &[],
    );
    assert_eq!(recovered["mode"], "RecoveryReadOnly");
    assert_eq!(recovered["entries"][0]["id"], id);
    assert_eq!(recovered["revision"], derived["revision"]);
}

#[test]
fn retry_pagination_and_delete_are_durable() {
    let c = Cli::new();
    c.init();
    let id = "01010101010101010101010101010101";
    let request = "0202020202020202020202020202020202020202020202020202020202020202";
    let args = [
        "--request",
        request,
        "add",
        "password",
        "--id",
        id,
        "--label",
        "test",
        "--scope",
        "example.test",
        "--revealable",
    ];
    let first = c.ok(&args, &[UNLOCK, "synthetic-service-password"]);
    let retry = c.ok(&args, &[UNLOCK, "synthetic-service-password"]);
    assert_eq!(first["revision"], retry["revision"]);
    let conflict = c.run(&args, &[UNLOCK, "different-synthetic-password"]);
    assert!(!conflict.status.success());
    let second = c.ok(
        &["add", "pin", "--label", "second", "--scope", "example.test"],
        &[UNLOCK, "1234"],
    );
    let list = c.ok(&["list", "--limit", "1"], &[UNLOCK]);
    assert_eq!(list["entries"].as_array().unwrap().len(), 1);
    let next = c.ok(
        &[
            "list",
            "--after",
            list["after"].as_str().unwrap(),
            "--limit",
            "1",
        ],
        &[UNLOCK],
    );
    assert_eq!(next["entries"].as_array().unwrap().len(), 1);
    assert_ne!(list["entries"][0]["id"], next["entries"][0]["id"]);
    let all = c.ok(&["list"], &[UNLOCK]);
    let entry = all["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == second["id"])
        .unwrap();
    c.ok(
        &[
            "remove",
            entry["id"].as_str().unwrap(),
            "--version",
            &entry["version"].to_string(),
        ],
        &[UNLOCK],
    );
    let list = c.ok(&["list"], &[UNLOCK]);
    assert_eq!(list["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn rejects_database_rollback_existing_recovery_and_insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let c = Cli::new();
    c.init();
    let factor = std::fs::read(c.path("recovery")).unwrap();
    assert_eq!(factor.len(), 32);
    assert_eq!(
        std::fs::metadata(c.path("recovery"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let retry = c.run(&["init", "--recovery-file", &c.path("recovery")], &[]);
    assert!(!retry.status.success());
    assert_eq!(std::fs::read(c.path("recovery")).unwrap(), factor);
    let old = std::fs::read(c.home.join("host.json")).unwrap();
    c.ok(
        &[
            "add",
            "domain-root",
            "--label",
            "root",
            "--scope",
            "example.test",
        ],
        &[UNLOCK],
    );
    std::fs::write(c.home.join("host.json"), old).unwrap();
    let stale = c.run(&["list"], &[UNLOCK]);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("StaleAnchor"));
    std::fs::set_permissions(&c.home, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!c.run(&["status"], &[]).status.success());
}

#[test]
fn help_exposes_spell_without_secret_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args(["add", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("spell"));
    assert!(!text.contains("mnemonic"));
    assert!(!text.contains("--password"));
    assert!(!text.contains("--value"));
}
