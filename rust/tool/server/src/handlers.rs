use std::{io::Read, path::PathBuf};

use lanzaboote_tool::{
    pe::StubParameters,
    signature::{remote::VerificationResponse, LanzabooteSigner},
    utils::SecureTempDirExt,
};
use log::{debug, trace, warn};
use rouille::{try_or_400, Request, Response};
use thiserror::Error;

use crate::policy::{Policy, TrivialPolicy};

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("body was already opened in request")]
    BodyAlreadyOpened,
}

pub struct Handlers<S: LanzabooteSigner> {
    policy: TrivialPolicy,
    signer: S,
}

impl<S: LanzabooteSigner> Handlers<S> {
    pub fn new(signer: S, policy: TrivialPolicy) -> Self {
        Self { signer, policy }
    }

    pub fn sign_stub(&self, req: &Request) -> Response {
        debug!("Signing stub request");
        let stub_parameters: StubParameters = try_or_400!(rouille::input::json_input(req));
        trace!("Stub parameters: {:#?}", stub_parameters);

        // Validate the stub according to the policy
        if !self.policy.trusted_stub_parameters(&stub_parameters) {
            warn!("Untrusted stub parameters");
            return Response::empty_400();
        }

        let working_tree = tempfile::tempdir().expect("Failed to create a directory");

        // Assemble the stub
        let image = stub_parameters
            .into_image()
            .expect("Failed to build the stub");

        // Sign the stub now
        let image_from = working_tree
            .write_secure_file(image)
            .expect("Failed to write a file in a secure fashion in the temporary working tree");
        let image_to = image_from.with_extension(".signed");
        self.signer.sign_and_copy(&image_from, &image_to).unwrap();

        Response::from_data(
            "application/octet-stream",
            std::fs::read(image_to).expect("Failed to read the stub"),
        )
    }

    pub fn sign_store_path(&self, req: &Request) -> Response {
        debug!("Signing store path request");
        let store_path: PathBuf = PathBuf::from(try_or_400!(rouille::input::plain_text_body(req)));
        debug!("Request for {}", store_path.display());

        if !self.policy.trusted_store_path(&store_path) {
            warn!("Untrusted store path: {}", store_path.display());
            Response::empty_400()
        } else {
            Response::from_data(
                "application/octet-stream",
                self.signer.sign_store_path(&store_path).unwrap(),
            )
        }
    }

    pub fn verify(&self, req: &Request) -> Response {
        let mut data = try_or_400!(req.data().ok_or(ErrorKind::BodyAlreadyOpened));
        let mut buf = Vec::new();
        try_or_400!(data.read_to_end(&mut buf));

        let signed_according_to_signer = self.signer.verify(buf.as_slice()).unwrap();

        Response::json(&VerificationResponse {
            signed: signed_according_to_signer,
            valid_according_secureboot_policy: signed_according_to_signer,
        })
    }
}
