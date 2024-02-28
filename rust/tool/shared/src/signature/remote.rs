use std::time::Duration;

use crate::pe::StubParameters;

use super::LanzabooteSigner;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use ureq::{Agent, AgentBuilder};
use url::Url;

/// Remote signing server
///
/// It will perform classical signature operations over HTTP
/// using the "Lanzaboote Remote Signing server" API.
///
/// This API relies on the server exposing three endpoints:
///
/// - `/sign/stub`: takes a StubParameter as input and reply with a signed stub
/// - `/sign/store-path`: takes a string store path as input and reply with the signed data
/// - `/verify`: takes PE binary as input and reply a `VerificationResponse`
///
/// lanzasignd is an example of implementation.
pub struct RemoteSigningServer {
    server_url: Url,
    user_agent: String,
    client: Agent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResponse {
    /// If the binary has any signature attached
    pub signed: bool,
    /// If the binary is valid according to the Secure Boot policy
    /// attached to this machine
    /// This is not always a reliable piece of information
    /// TODO: rework me.
    pub valid_according_secureboot_policy: bool,
}

impl RemoteSigningServer {
    pub fn new(server_url: &str, user_agent: &str) -> Result<Self> {
        let client = AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();
        Ok(Self {
            server_url: Url::parse(server_url)
                .with_context(|| format!("Failed to parse {} as an URL", server_url))?,
            user_agent: user_agent.to_string(),
            client,
        })
    }

    /// Asks for the remote server to send back a stub
    /// assembled with the parameters provided.
    ///
    /// If the remote server agrees on providing that stub
    /// It will return it signed.
    fn request_signature(&self, stub_parameters: &StubParameters) -> Result<Vec<u8>> {
        if !stub_parameters.all_signables_in_store() {
            bail!("Signable stub parameters contains non-Nix store paths, the remote server cannot sign that!");
        }

        let response = self
            .client
            .post(self.server_url.join("/sign/stub")?.as_str())
            .set("User-Agent", &self.user_agent)
            .send_json(stub_parameters)
            .context("Failed to request signature")?;

        let len: Option<usize> = if response.has("Transfer-Encoding")
            && response.header("Transfer-Encoding").unwrap() == "chunked"
        {
            None
        } else {
            Some(
                response
                    .header("Content-Length")
                    .ok_or(anyhow::anyhow!(
                        "No content length in server response for stub signature"
                    ))?
                    .parse()?,
            )
        };

        let mut reader = response.into_reader();

        let mut binary = match len {
            Some(len) => Vec::with_capacity(len),
            None => Vec::new(),
        };

        reader.read_to_end(&mut binary)?;

        Ok(binary)
    }

    /// Asks for the remote server to sign an arbitrary
    /// store path.
    fn request_store_path_signature(&self, store_path: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(self.server_url.join("/sign/store-path")?.as_str())
            .set("User-Agent", &self.user_agent)
            .set("Content-Type", "text/plain; charset=utf8")
            .send_string(store_path)
            .context("Failed to request signature")?;

        let len: Option<usize> = if response.has("Transfer-Encoding")
            && response.header("Transfer-Encoding").unwrap() == "chunked"
        {
            None
        } else {
            Some(
                response
                    .header("Content-Length")
                    .ok_or(anyhow::anyhow!(
                        "No content length in server response for stub signature"
                    ))?
                    .parse()?,
            )
        };

        let mut reader = response.into_reader();

        let mut binary = match len {
            Some(len) => Vec::with_capacity(len),
            None => Vec::new(),
        };

        reader.read_to_end(&mut binary)?;

        Ok(binary)
    }
}

impl LanzabooteSigner for RemoteSigningServer {
    fn get_public_key(&self) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(self.server_url.join("/publickey")?.as_str())
            .set("User-Agent", &self.user_agent)
            .set("Content-Type", "application/octet-stream")
            .call()
            .context("Failed to request public key")?;

        let len: Option<usize> = if response.has("Transfer-Encoding")
            && response.header("Transfer-Encoding").unwrap() == "chunked"
        {
            None
        } else {
            Some(
                response
                    .header("Content-Length")
                    .ok_or(anyhow::anyhow!(
                        "No content length in server response for stub signature"
                    ))?
                    .parse()?,
            )
        };

        let mut reader = response.into_reader();

        let mut binary = match len {
            Some(len) => Vec::with_capacity(len),
            None => Vec::new(),
        };

        reader.read_to_end(&mut binary)?;
        Ok(binary)
    }

    fn can_sign_stub(&self, stub: &StubParameters) -> bool {
        stub.all_signables_in_store()
    }

    fn build_and_sign_stub(&self, stub: &StubParameters) -> Result<Vec<u8>> {
        self.request_signature(stub)
    }
    fn sign_store_path(&self, store_path: &std::path::Path) -> Result<Vec<u8>> {
        self.request_store_path_signature(
            store_path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Failed to transform store path into valid UTF-8")
            })?,
        )
    }

    fn verify(&self, pe_binary: &[u8]) -> Result<bool> {
        let resp: VerificationResponse = self
            .client
            .post(self.server_url.join("/verify")?.as_str())
            .set("User-Agent", &self.user_agent)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(pe_binary)
            .context("Failed to request verification")?
            .into_json()?;

        Ok(resp.signed)
    }
}
