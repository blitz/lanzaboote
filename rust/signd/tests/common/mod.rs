use std::{fs, path::Path};

use lanzaboote_signd::{handlers::Handlers, policy::Policy, route};
use lanzaboote_tool::{
    architecture::Architecture,
    pe::StubParameters,
    signature::{local::LocalKeyPair, remote::RemoteSigningServer},
};
use rouille::{Request, Response};

/// Returns the host platform system
/// in the system double format for
/// our usual targets.
#[cfg(target_arch = "aarch64")]
pub static SYSTEM: &str = "aarch64-linux";

// We do not actually care much about 32 bit. However we can use this to easily test that lzbt
// works with another architecture.
#[cfg(target_arch = "x86")]
pub static SYSTEM: &str = "i686-linux";

#[cfg(target_arch = "x86_64")]
pub static SYSTEM: &str = "x86_64-linux";

/// An policy that should never ever be used in production.
pub struct AbsolutelyInsecurePolicy;

impl Policy for AbsolutelyInsecurePolicy {
    fn trusted_store_path(&self, store_path: &std::path::Path) -> bool {
        true
    }

    fn trusted_stub_parameters(&self, parameters: &lanzaboote_tool::pe::StubParameters) -> bool {
        true
    }
}

pub fn setup_keypair() -> LocalKeyPair {
    LocalKeyPair::new(
        Path::new("../../tool/tests/fixtures/uefi-keys/db.pem"),
        Path::new("../../tool/tests/fixtures/uefi-keys/db.key"),
    )
}

pub fn setup() -> (
    rouille::Server<impl Fn(&Request) -> Response>,
    RemoteSigningServer,
) {
    let keypair = setup_keypair();

    let handlers = Handlers::new(keypair, AbsolutelyInsecurePolicy);
    let server = rouille::Server::new("localhost:0", route(handlers))
        .expect("Failed to start the HTTP server");
    let server_url = format!("http://localhost:{}", server.server_addr().port());
    let remote_signer = RemoteSigningServer::new(&server_url, "rustc/integration testing")
        .expect("Failed to build the remote signer");

    (server, remote_signer)
}

/// Stolen from `tool` setup.
/// Setup a mock toplevel inside a temporary directory.
///
/// Accepts the temporary directory as a parameter so that the invoking function retains control of
/// it (and when it goes out of scope).
pub fn setup_toplevel(tmpdir: &Path) -> std::io::Result<StubParameters> {
    let system = Architecture::from_nixos_system(SYSTEM)?;

    // Generate a random toplevel name so that multiple toplevel paths can live alongside each
    // other in the same directory.
    let toplevel = tmpdir.join(format!("toplevel-{}", random_string(8)));
    let fake_store_path = toplevel.join("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-6.1.1");
    fs::create_dir_all(&fake_store_path)?;

    let test_systemd = systemd_location_from_env()?;
    let systemd_stub_filename = system.systemd_stub_filename();
    let test_systemd_stub = format!(
        "{test_systemd}/lib/systemd/boot/efi/{systemd_stub_filename}",
        systemd_stub_filename = systemd_stub_filename.display()
    );

    let initrd_path = fake_store_path.join("initrd");
    let kernel_path = fake_store_path.join("kernel");
    let nixos_version_path = toplevel.join("nixos-version");
    let kernel_modules_path = toplevel.join("kernel-modules/lib/modules/6.1.1");

    // To simplify the test setup, we use the systemd stub for all PE binaries used by lanzatool.
    // Lanzatool doesn't care whether its actually a kernel or initrd but only whether it can
    // manipulate the PE binary with objcopy and/or sign it with sbsigntool. For testing lanzatool
    // in isolation this should suffice.
    fs::copy(&test_systemd_stub, initrd_path)?;
    fs::copy(&test_systemd_stub, kernel_path)?;
    fs::write(nixos_version_path, b"23.05")?;
    fs::create_dir_all(kernel_modules_path)?;

    Ok(toplevel)
}
