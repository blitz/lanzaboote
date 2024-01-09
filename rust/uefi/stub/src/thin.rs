use log::{error, warn};
use sha2::{Digest, Sha256};
use uefi::{fs::FileSystem, proto::loaded_image::LoadedImage, prelude::*, CStr16, CString16, Result};
use uefi::proto::network::IpAddress;
use uefi::proto::network::pxe::{BaseCode, DhcpV4Packet};

use crate::common::{boot_linux_unchecked, extract_string, get_cmdline, get_secure_boot_status};
use linux_bootloader::pe_section::pe_section;
use linux_bootloader::uefi_helpers::booted_image_file;

type Hash = sha2::digest::Output<Sha256>;

/// The configuration that is embedded at build time.
///
/// After this stub is built, lzbt needs to embed configuration into the binary by adding PE
/// sections. This struct represents that information.
struct EmbeddedConfiguration {
    /// The filename of the kernel to be booted. This filename is
    /// relative to the root of the volume that contains the
    /// lanzaboote binary.
    kernel_filename: CString16,

    /// The cryptographic hash of the kernel.
    kernel_hash: Hash,

    /// The filename of the initrd to be passed to the kernel. See
    /// `kernel_filename` for how to interpret these filenames.
    initrd_filename: CString16,

    /// The cryptographic hash of the initrd. This hash is computed
    /// over the whole PE binary, not only the embedded initrd.
    initrd_hash: Hash,

    /// The kernel command-line.
    cmdline: CString16,
}

/// Extract a SHA256 hash from a PE section.
fn extract_hash(pe_data: &[u8], section: &str) -> Result<Hash> {
    let array: [u8; 32] = pe_section(pe_data, section)
        .ok_or(Status::INVALID_PARAMETER)?
        .try_into()
        .map_err(|_| Status::INVALID_PARAMETER)?;

    Ok(array.into())
}

impl EmbeddedConfiguration {
    fn new(file_data: &[u8]) -> Result<Self> {
        Ok(Self {
            kernel_filename: extract_string(file_data, ".kernelp")?,
            kernel_hash: extract_hash(file_data, ".kernelh")?,

            initrd_filename: extract_string(file_data, ".initrdp")?,
            initrd_hash: extract_hash(file_data, ".initrdh")?,

            cmdline: extract_string(file_data, ".cmdline")?,
        })
    }
}

/// Verify some data against its expected hash.
///
/// In case of a mismatch:
/// * If Secure Boot is active, an error message is logged, and the SECURITY_VIOLATION error is returned to stop the boot.
/// * If Secure Boot is not active, only a warning is logged, and the boot process is allowed to continue.
fn check_hash(data: &[u8], expected_hash: Hash, name: &str, secure_boot: bool) -> uefi::Result<()> {
    let hash_correct = Sha256::digest(data) == expected_hash;
    if !hash_correct {
        if secure_boot {
            error!("{name} hash does not match!");
            return Err(Status::SECURITY_VIOLATION.into());
        } else {
            warn!("{name} hash does not match! Continuing anyway.");
        }
    }
    Ok(())
}

pub fn boot_linux(handle: Handle, mut system_table: SystemTable<Boot>) -> uefi::Result<()> {
    uefi_services::init(&mut system_table).unwrap();

    // SAFETY: We get a slice that represents our currently running
    // image and then parse the PE data structures from it. This is
    // safe, because we don't touch any data in the data sections that
    // might conceivably change while we look at the slice.
    let config = unsafe {
        EmbeddedConfiguration::new(
            booted_image_file(system_table.boot_services())
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to extract configuration from binary. Did you run lzbt?")
    };

    let secure_boot_enabled = get_secure_boot_status(system_table.runtime_services());

    let mut kernel_data;
    let mut initrd_data;

    {
        let file_system = system_table
            .boot_services()
            .get_image_file_system(handle)
            .expect("Failed to get file system handle");
        let mut file_system = FileSystem::new(file_system);

        if system_table.boot_services().test_protocol::<uefi::proto::media::fs::SimpleFileSystem>(filesystem_protocol_params).is_ok() {
            let mut file_system = system_table
                .boot_services()
                .get_image_file_system(handle)
                .expect("Failed to get file system handle");

            kernel_data = file_system
                .read(&*config.kernel_filename)
                .expect("Failed to read kernel file into memory");
            initrd_data = file_system
                .read(&*config.initrd_filename)
                .expect("Failed to read initrd file into memory");
        } else {
            let loaded_image_protocol = system_table.boot_services().open_protocol_exclusive::<LoadedImage>(system_table.boot_services().image_handle())
                .expect("Failed to open the loaded image protocol on the currently loaded image");

            let mut base_code = system_table.boot_services().open_protocol_exclusive::<BaseCode>(loaded_image_protocol.device()).unwrap();

            assert!(base_code.mode().dhcp_ack_received);
            let dhcp_ack: &DhcpV4Packet = base_code.mode().dhcp_ack.as_ref();
            let server_ip = dhcp_ack.bootp_si_addr;
            let server_ip = IpAddress::new_v4(server_ip);

            let kernel_filename = cstr8!("./bzImage");
            let initrd_filename = cstr8!("./initrd");

            let kfile_size = base_code
                .tftp_get_file_size(&server_ip, kernel_filename)
                .expect("failed to query file size");

            let ifile_size = base_code
                .tftp_get_file_size(&server_ip, initrd_filename)
                .expect("failed to query file size");

            assert!(kfile_size > 0);
            assert!(ifile_size > 0);

            kernel_data = Vec::with_capacity(kfile_size as usize);
            kernel_data.resize(kfile_size as usize, 0);
            initrd_data = Vec::with_capacity(ifile_size as usize);
            initrd_data.resize(ifile_size as usize, 0);
            let klen = base_code
                .tftp_read_file(&server_ip, kernel_filename, Some(&mut kernel_data))
                .expect("failed to read file");
            let ilen = base_code
                .tftp_read_file(&server_ip, initrd_filename, Some(&mut initrd_data))
                .expect("failed to read file");

            assert!(klen > 0);
            assert!(ilen > 0);
        }
    }

    let cmdline = get_cmdline(
        &config.cmdline,
        system_table.boot_services(),
        secure_boot_enabled,
    );

    check_hash(
        &kernel_data,
        config.kernel_hash,
        "Kernel",
        secure_boot_enabled,
    )?;
    check_hash(
        &initrd_data,
        config.initrd_hash,
        "Initrd",
        secure_boot_enabled,
    )?;

    boot_linux_unchecked(handle, system_table, kernel_data, &cmdline, initrd_data)
}
