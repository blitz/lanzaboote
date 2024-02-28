use lanzaboote_tool::pe::StubParameters;

mod common;

#[test]
fn test_sign_and_verify() {
    let (server, remote_signer) = common::setup();
    let stub_parameters = common::setup_toplevel(tmpdir());
    remote_signer.build_and_sign_stub(stub_parameters);
}
