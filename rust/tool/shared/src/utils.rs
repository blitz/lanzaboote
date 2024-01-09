use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::iter::repeat_with;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// The number of random alphanumeric characters in the tempfiles.
const TEMPFILE_RANDOM_LENGTH: usize = 32;

/// Extension for a temporary directory that enables creating secure temporary files in it.
pub trait SecureTempDirExt {
    fn create_secure_file(&self, path: &Path) -> Result<fs::File>;
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf>;
}

/// This implementation has three useful properties:
///
/// - Files are created with mode 0o600, so that they are only accessible by the current user.
/// - Files are named and not ephemeral (unlike a real temporary file).
/// - The directory and its children are cleaned up (i.e. deleted) when the variable that holds the
///   directory goes out of scope.
///
/// This protects against an attacker _without_ root access from modifying files undetected. It
/// provides no prection against an attacker _with_ root access. Additionally, because the files
/// have named paths, they can be passed to external programs while still being securely deleted
/// after they are not needed anymore.
impl SecureTempDirExt for TempDir {
    /// Create a temporary file that can only be accessed by the current Linux user.
    fn create_secure_file(&self, path: &Path) -> Result<fs::File> {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create tempfile: {path:?}"))
    }

    /// Create a temporary file and write a `u8` slice to it.
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
        let path = self.path().join(tmpname());
        let mut tmpfile = self.create_secure_file(&path)?;

        tmpfile
            .write_all(contents.as_ref())
            .with_context(|| format!("Failed to write to tempfile {path:?}"))?;

        Ok(path)
    }
}

/// Generate a random (but not cryptographically secure) name for a temporary file.
///
/// This is heavily inspired by the way temporary names are generated in the `tempfile` crate.
/// Since the `tempfile` crate does not expose this functionality, we have to recreate it here.
pub fn tmpname() -> OsString {
    let mut buf = OsString::with_capacity(TEMPFILE_RANDOM_LENGTH);
    let mut char_buf = [0u8; 4];
    for c in repeat_with(fastrand::alphanumeric).take(TEMPFILE_RANDOM_LENGTH) {
        buf.push(c.encode_utf8(&mut char_buf));
    }
    buf
}

type Hash = sha2::digest::Output<Sha256>;

/// Compute the SHA 256 hash of a file.
pub fn file_hash(file: &Path) -> Result<Hash> {
    Ok(Sha256::digest(fs::read(file).with_context(|| {
        format!("Failed to read file to hash: {file:?}")
    })?))
}

pub fn assemble_kernel_cmdline(init: &Path, kernel_params: Vec<String>) -> Vec<String> {
    let init_string = String::from(
        init.to_str()
            .expect("Failed to convert init path to string"),
    );
    let mut kernel_cmdline: Vec<String> = vec![format!("init={}", init_string)];
    kernel_cmdline.extend(kernel_params);
    kernel_cmdline
}
