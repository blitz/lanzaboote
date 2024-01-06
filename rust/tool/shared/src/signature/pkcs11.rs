use crate::pe::lanzaboote_image;

use super::LanzabooteSigner;
use anyhow::Context;
use cryptoki::{context::Pkcs11, session::Session};
use signature::Keypair;
use tempfile::tempdir;

pub type P256Signer<S> = cryptoki_rustcrypto::ecdsa::Signer<p256::NistP256, S>;

/// This can only really sign PE binaries and nothing else.
pub struct Pkcs11Signer {
    context: Pkcs11,
    token_uri: String,
    session: Session,
    /// Signing certificate for this signer
    /// FIXME: CA/SubCA/Leaf setup are not supported yet.
    pub signing_certificate: x509_cert::Certificate,
    pub signer: P256Signer<Session>,
}

impl Pkcs11Signer {
    fn new(&self, context: Pkcs11, token_uri: String) -> Self {
        // TODO: if there's a pin in the token_uri, done
        // if there's no pin, start user interaction.
        // login the session.
        // fetch the signing certificate: input is label and subject.
        Self { context, token_uri }
    }

    fn sign_bytes(&self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let pe = goblin::pe::PE::parse(bytes)?;
        let pe_certificate = goblin_signing::sign::create_certificate(
            &pe,
            vec![self.signing_certificate.clone()],
            self.signing_certificate.clone(),
            &self.signer,
        );
    }
}

impl LanzabooteSigner for Pkcs11Signer {
    fn get_public_key(&self) -> anyhow::Result<Box<[u8]>> {
        Ok(self.signer.verifying_key().to_sec1_bytes())
    }

    fn sign_store_path(&self, store_path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
        let contents = std::fs::read(store_path)?;
        self.sign_bytes(&contents)
    }

    fn build_and_sign_stub(&self, stub: &crate::pe::StubParameters) -> anyhow::Result<Vec<u8>> {
        let working_tree = tempdir()?;
        let lzbt_image_path =
            lanzaboote_image(&working_tree, stub).context("Failed to build a lanzaboote image")?;
        let to = working_tree.path().join("signed-stub.efi");
        self.sign_and_copy(&lzbt_image_path, &to);

        std::fs::read(&to).context("Failed to read a lanzaboote image")
    }

    fn can_sign_stub(&self, stub: &crate::pe::StubParameters) -> bool {
        // If we can login and we have a RW session,
        // we can sign any stub, yes.
        true
    }

    fn verify(&self, pe_binary: &[u8]) -> anyhow::Result<bool> {
        Ok(
            goblin_signing::verify::verify_pe_signatures_no_trust(&goblin::pe::PE::parse(
                pe_binary,
            )?)?
            .0,
        )
    }
}
