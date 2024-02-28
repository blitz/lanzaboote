use lanzaboote_tool::signature::LanzabooteSigner;
use log::trace;
use policy::Policy;
use rouille::{router, Request, Response};

pub mod handlers;
pub mod policy;

pub fn route<S: LanzabooteSigner, P: Policy>(
    handlers: handlers::Handlers<S, P>,
) -> impl Fn(&Request) -> Response {
    move |request| {
        trace!("Receiving {:#?}", request);
        router!(request,
            (POST) (/sign/stub) => {
                handlers.sign_stub(request)
            },
            (POST) (/sign/store-path) => {
                handlers.sign_store_path(request)
            },
            (POST) (/verify) => {
                handlers.verify(request)
            },
            _ => {
                Response::text("lanzasignd signature endpoint")
            }
        )
    }
}
