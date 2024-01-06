use anyhow::Result;
use std::path::Path;

use crate::pe::StubParameters;

pub trait LanzabooteSigner {
    fn sign_store_path(&self, store_path: &Path) -> Result<Vec<u8>>;
    fn can_sign_stub(&self, stub: &StubParameters) -> bool;
    fn build_and_sign_stub(&self, stub: &StubParameters) -> Result<Vec<u8>>;
    fn get_public_key(&self) -> Result<Vec<u8>>;

    fn sign_and_copy(&self, from: &Path, to: &Path) -> Result<()> {
        Ok(std::fs::write(to, self.sign_store_path(from)?)?)
    }

    /// Verify the signature of a PE binary, provided as bytes.
    /// Return true if the signature was verified.
    fn verify(&self, pe_binary: &[u8]) -> Result<bool>;
    /// Verify the signature of a PE binary, provided by its path.
    /// Return true if the signature was verified.
    fn verify_path(&self, from: &Path) -> Result<bool> {
        self.verify(&std::fs::read(from).expect("Failed to read the path to verify"))
    }
}

pub mod local;
pub mod remote;
