use super::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, IsTerminal, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub fn secret(prompt: &str, piped: bool) -> Result<Zeroizing<String>> {
    let value = if piped {
        if std::io::stdin().is_terminal() {
            return Err("--secrets-stdin requires a pipe, not an echoing terminal".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let n = std::io::stdin()
            .lock()
            .take((crate::MAX_SECRET_BYTES + 2) as u64)
            .read_until(b'\n', &mut bytes)?;
        if n == 0 || bytes.last() != Some(&b'\n') {
            return Err("secret input must be a bounded newline-terminated line".into());
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| "invalid secret encoding")?
                .to_owned(),
        )
    } else {
        Zeroizing::new(rpassword::prompt_password(prompt).map_err(
            |_| "hidden terminal input unavailable; a trusted pipe may use --secrets-stdin",
        )?)
    };
    if value.len() > crate::MAX_SECRET_BYTES {
        return Err("secret exceeds the per-value byte limit".into());
    }
    Ok(value)
}

pub fn tty() -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "protected output requires a controlling terminal")?;
    if !file.is_terminal() {
        return Err("protected output requires a controlling terminal".into());
    }
    Ok(file)
}

pub fn check_private(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || (!directory && meta.nlink() != 1)
    {
        return Err(
            "host paths must be owner-only, owned by the current user, and not links".into(),
        );
    }
    Ok(())
}

pub fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.try_exists()? {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    check_private(path, true)
}

pub fn lock(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    if path.try_exists()? {
        check_private(path, false)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    check_private(path, false)?;
    file.try_lock()
        .map_err(|_| "another Vault process owns this host")?;
    Ok(file)
}

pub fn new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        check_private(path, false)?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().ok_or("missing parent")?)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|_| "cannot replace host checkpoint")?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

pub fn read_private(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    check_private(path, false)?;
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("host file exceeds its format limit".into());
    }
    Ok(bytes)
}

pub fn array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| "invalid hex identifier")?;
    Ok(bytes)
}
