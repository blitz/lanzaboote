use std::{io::Read, path::PathBuf};

use lanzaboote_tool::{
    pe::{lanzaboote_image, StubParameters},
    signature::{remote::VerificationResponse, LanzabooteSigner},
};
use log::{debug, trace, warn};
use rouille::{try_or_400, Request, Response};
use thiserror::Error;

use crate::policy::Policy;

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("body was already opened in request")]
    BodyAlreadyOpened,
}

pub struct Handlers<S: LanzabooteSigner, P: Policy> {
    policy: P,
    signer: S,
}

impl<S: LanzabooteSigner, P: Policy> Handlers<S, P> {
    pub fn new(signer: S, policy: P) -> Self {
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
        let image =
            lanzaboote_image(&working_tree, &stub_parameters).expect("Failed to build the stub");

        // Sign the stub now
        let image_to = image.with_extension(".signed");
        self.signer.sign_and_copy(&image, &image_to).unwrap();

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
