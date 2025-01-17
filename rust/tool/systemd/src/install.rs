use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::{OsStrExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::string::ToString;

use anyhow::{anyhow, Context, Result};
use base32ct::{Base32Unpadded, Encoding};
use nix::unistd::syncfs;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::architecture::SystemdArchitectureExt;
use crate::esp::SystemdEspPaths;
use crate::version::SystemdVersion;
use lanzaboote_tool::architecture::Architecture;
use lanzaboote_tool::esp::EspPaths;
use lanzaboote_tool::gc::Roots;
use lanzaboote_tool::generation::{Generation, GenerationLink};
use lanzaboote_tool::os_release::OsRelease;
use lanzaboote_tool::pe::{self, append_initrd_secrets, lanzaboote_image};
use lanzaboote_tool::signature::Signer;
use lanzaboote_tool::utils::{file_hash, SecureTempDirExt};

pub struct Installer<S: Signer> {
    broken_gens: BTreeSet<u64>,
    gc_roots: Roots,
    lanzaboote_stub: PathBuf,
    systemd: PathBuf,
    systemd_boot_loader_config: PathBuf,
    signer: S,
    configuration_limit: usize,
    esp_paths: SystemdEspPaths,
    generation_links: Vec<PathBuf>,
    arch: Architecture,
}

#[allow(clippy::too_many_arguments)]
impl<S: Signer> Installer<S> {
    pub fn new(
        lanzaboote_stub: PathBuf,
        arch: Architecture,
        systemd: PathBuf,
        systemd_boot_loader_config: PathBuf,
        signer: S,
        configuration_limit: usize,
        esp: PathBuf,
        generation_links: Vec<PathBuf>,
    ) -> Self {
        let mut gc_roots = Roots::new();
        let esp_paths = SystemdEspPaths::new(esp, arch);
        gc_roots.extend(esp_paths.iter());

        Self {
            broken_gens: BTreeSet::new(),
            gc_roots,
            lanzaboote_stub,
            systemd,
            systemd_boot_loader_config,
            signer,
            configuration_limit,
            esp_paths,
            generation_links,
            arch,
        }
    }

    pub fn install(&mut self) -> Result<()> {
        log::info!("Installing Lanzaboote to {:?}...", self.esp_paths.esp);

        let mut links = self
            .generation_links
            .iter()
            .map(GenerationLink::from_path)
            .collect::<Result<Vec<GenerationLink>>>()?;

        // Sort the links by version, so that the limit actually skips the oldest generations.
        links.sort_by_key(|l| l.version);

        // A configuration limit of 0 means there is no limit.
        if self.configuration_limit > 0 {
            // Only install the number of generations configured. Reverse the list to only take the
            // latest generations and then, after taking them, reverse the list again so that the
            // generations are installed from oldest to newest, i.e. from smallest to largest
            // generation version.
            links = links
                .into_iter()
                .rev()
                .take(self.configuration_limit)
                .rev()
                .collect()
        };
        self.install_generations_from_links(&links)?;

        self.install_systemd_boot()?;

        if self.broken_gens.is_empty() {
            log::info!("Collecting garbage...");
            // Only collect garbage in these two directories. This way, no files that do not belong to
            // the NixOS installation are deleted. Lanzatool takes full control over the esp/EFI/nixos
            // directory and deletes ALL files that it doesn't know about. Dual- or multiboot setups
            // that need files in this directory will NOT work.
            self.gc_roots.collect_garbage(&self.esp_paths.nixos)?;
            // The esp/EFI/Linux directory is assumed to be potentially shared with other distros.
            // Thus, only files that start with "nixos-" are garbage collected (i.e. potentially
            // deleted).
            self.gc_roots
                .collect_garbage_with_filter(&self.esp_paths.linux, |p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map_or(false, |n| n.starts_with("nixos-"))
                })?;
        } else {
            // This might produce a ridiculous message if you have a lot of malformed generations.
            let warning = indoc::formatdoc! {"
                Garbage collection is disabled because you have malformed NixOS generations that do
                not contain a readable bootspec document.

                Remove the malformed generations to re-enable garbage collection with
                `nix-env --delete-generations {}`
            ", self.broken_gens.iter().map(ToString::to_string).collect::<Vec<String>>().join(" ")};
            log::warn!("{warning}");
        };

        log::info!("Successfully installed Lanzaboote.");
        Ok(())
    }

    /// Install all generations from the provided `GenerationLinks`.
    fn install_generations_from_links(&mut self, links: &[GenerationLink]) -> Result<()> {
        let generations = links
            .iter()
            .filter_map(|link| {
                let generation_result = Generation::from_link(link)
                    .with_context(|| format!("Failed to build generation from link: {link:?}"));

                // Ignore failing to read a generation so that old malformed generations do not stop
                // lzbt from working.
                if generation_result.is_err() {
                    // If there is ANY malformed generation present, completely disable all garbage
                    // collection to protect the old generations from being deleted. The user has
                    // to manually intervene by getting rid of the old generations to re-enable
                    // garbage collection. This safeguard against catastrophic failure in case of
                    // unhandled upstream changes to NixOS.
                    self.broken_gens.insert(link.version);
                }

                generation_result.ok()
            })
            .collect::<Vec<Generation>>();

        if generations.is_empty() {
            // We can't continue, because we would remove all boot entries, if we did.
            return Err(anyhow!("No bootable generations found! Aborting to avoid unbootable system. Please check for Lanzaboote updates!"));
        }

        for generation in generations {
            // The kernels and initrds are content-addressed.
            // Thus, this cannot overwrite files of old generation with different content.
            self.install_generation(&generation)
                .with_context(|| format!("Failed to install generation {}", generation.version))?;
            for (name, bootspec) in &generation.spec.bootspec.specialisations {
                let specialised_generation = generation.specialise(name, bootspec);
                self.install_generation(&specialised_generation)
                    .context("Failed to install specialisation.")?;
            }
        }

        // Sync files to persistent storage. This may improve the
        // chance of a consistent boot directory in case the system
        // crashes.
        let boot = File::open(&self.esp_paths.esp).context("Failed to open ESP root directory.")?;
        syncfs(boot.as_raw_fd()).context("Failed to sync ESP filesystem.")?;

        Ok(())
    }

    /// Install the given `Generation`.
    ///
    /// The kernel and initrd are content-addressed, and the stub name identifies the generation.
    /// Hence, this function cannot overwrite files of other generations with different contents.
    /// All installed files are added as garbage collector roots.
    fn install_generation(&mut self, generation: &Generation) -> Result<()> {
        // If the generation is already properly installed, don't overwrite it.
        if self.register_installed_generation(generation).is_ok() {
            return Ok(());
        }

        let tempdir = TempDir::new().context("Failed to create temporary directory.")?;
        let bootspec = &generation.spec.bootspec.bootspec;

        // The kernel is a file in /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-linux-<version>/.
        // (On x86, that file is called bzImage, but other architectures may differ.)
        let kernel_dirname = bootspec
            .kernel
            .parent()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            .context("Failed to extract the kernel directory name.")?;
        let kernel_version = kernel_dirname
            .rsplit('-')
            .next()
            .context("Failed to extract the kernel version.")?;

        // Install the kernel and record its path on the ESP.
        let kernel_target = self
            .install_nixos_ca(&bootspec.kernel, &format!("kernel-{}", kernel_version))
            .context("Failed to install the kernel.")?;

        // Assemble and install the initrd, and record its path on the ESP.
        // It is not needed to write the initrd in a temporary directory
        // if we do not have any initrd secret.
        let initrd_location = if bootspec.initrd_secrets.is_some() {
            tempdir
                .write_secure_file(
                    fs::read(
                        bootspec
                            .initrd
                            .as_ref()
                            .context("Lanzaboote does not support missing initrd yet.")?,
                    )
                    .context("Failed to read the initrd.")?,
                )
                .context("Failed to copy the initrd to the temporary directory.")?
        } else {
            bootspec
                .initrd
                .clone()
                .expect("Lanzaboote does not support missing initrd yet.")
        };

        if let Some(initrd_secrets_script) = &bootspec.initrd_secrets {
            append_initrd_secrets(initrd_secrets_script, &initrd_location, generation.version)?;
        }
        let initrd_target = self
            .install_nixos_ca(&initrd_location, &format!("initrd-{}", kernel_version))
            .context("Failed to install the initrd.")?;

        // Assemble, sign and install the Lanzaboote stub.
        let os_release = OsRelease::from_generation(generation)
            .context("Failed to build OsRelease from generation.")?;

        let os_release_contents = os_release.to_string();

        let kernel_cmdline =
            assemble_kernel_cmdline(&bootspec.init, bootspec.kernel_params.clone());

        let parameters = pe::StubParameters::new(
            &self.lanzaboote_stub,
            &bootspec.kernel,
            &initrd_location,
            &kernel_target,
            &initrd_target,
            &self.esp_paths.esp,
        )?
        .with_cmdline(&kernel_cmdline)
        .with_os_release_contents(os_release_contents.as_bytes());

        let lanzaboote_image_path = lanzaboote_image(&tempdir, &parameters)
            .context("Failed to build and sign lanzaboote stub image.")?;

        let stub_target = self
            .esp_paths
            .linux
            .join(stub_name(generation, &self.signer).context("Get stub name")?);
        self.gc_roots.extend([&stub_target]);
        install_signed(&self.signer, &lanzaboote_image_path, &stub_target)
            .context("Failed to install the Lanzaboote stub.")?;

        if let Some(xen) = &generation.spec.xen_extension {
            use std::fmt::Write;
            let xen_image = pe::xen_image(
                &tempdir,
                &PathBuf::from(&xen.xen),
                &xen.xen_params,
                &kernel_cmdline,
                &PathBuf::from(&xen.vmlinux),
                &initrd_location,
            )
            .context("Failed to assemble xen image.")?;
            let stub_target = self
                .esp_paths
                .linux
                .join(stub_name(generation, &self.key_pair.public_key)?);
            self.gc_roots.extend([&stub_target]);
            install_signed(&self.key_pair, &xen_image, &stub_target)
                .context("Failed to install the Lanzaboote image.")?;

            // TODO: Currently xen doesn't work with specializations,
            // and specialization name is not handled here, but this may
            // be changed in the future.
            let entry_path = self
                .esp_paths
                .entries
                .join(format!("nixos-xen-{generation}.conf"));
            self.gc_roots.extend([&entry_path]);

            let mut entry = String::new();
            writeln!(
                entry,
                "title {}",
                os_release.0.get("PRETTY_NAME").expect("exists")
            )?;
            // stub_target should be utf-8, .display() is ok here.
            // TODO: but better cleanup this. Use esp_relative_uefi_path
            // for this calculation.
            writeln!(
                entry,
                "efi {}",
                stub_target.strip_prefix(&self.esp_paths.esp)?.display()
            )?;

            let entry_tmp = tempdir.write_secure_file(entry)?;

            // Entry name is unique (with regards to comment about
            // specialisations above).
            install(&entry_tmp, &entry_path)?;
        } else {
            let lanzaboote_image = pe::lanzaboote_image(
                &tempdir,
                &self.lanzaboote_stub,
                &os_release_path,
                &kernel_cmdline,
                &bootspec.kernel,
                &kernel_target,
                &initrd_location,
                &initrd_target,
                &self.esp_paths.esp,
            )
            .context("Failed to assemble lanzaboote image.")?;
            let stub_target = self
                .esp_paths
                .linux
                .join(stub_name(generation, &self.key_pair.public_key)?);
            self.gc_roots.extend([&stub_target]);
            install_signed(&self.key_pair, &lanzaboote_image, &stub_target)
                .context("Failed to install the Lanzaboote stub.")?;
        }

        Ok(())
    }

    /// Register the files of an already installed generation as garbage collection roots.
    ///
    /// An error should not be considered fatal; the generation should be (re-)installed instead.
    fn register_installed_generation(&mut self, generation: &Generation) -> Result<()> {
        let stub_target = self
            .esp_paths
            .linux
            .join(stub_name(generation, &self.signer).context("While getting stub name")?);
        let stub = fs::read(&stub_target)
            .with_context(|| format!("Failed to read the stub: {}", stub_target.display()))?;
        let kernel_path = resolve_efi_path(
            &self.esp_paths.esp,
            pe::read_section_data(&stub, ".linux").context("Missing kernel path.")?,
        )?;
        let initrd_path = resolve_efi_path(
            &self.esp_paths.esp,
            pe::read_section_data(&stub, ".initrd").context("Missing initrd path.")?,
        )?;

        if !kernel_path.exists() && !initrd_path.exists() {
            anyhow::bail!("Missing kernel or initrd.");
        }
        self.gc_roots
            .extend([&stub_target, &kernel_path, &initrd_path]);

        Ok(())
    }

    /// Install a content-addressed file to the `EFI/nixos` directory on the ESP.
    ///
    /// It is automatically added to the garbage collector roots.
    /// The full path to the target file is returned.
    fn install_nixos_ca(&mut self, from: &Path, label: &str) -> Result<PathBuf> {
        let hash = file_hash(from).context("Failed to read the source file.")?;
        let to = self.esp_paths.nixos.join(format!(
            "{}-{}.efi",
            label,
            Base32Unpadded::encode_string(&hash)
        ));
        self.gc_roots.extend([&to]);
        install(from, &to)?;
        Ok(to)
    }

    /// Install systemd-boot to ESP.
    ///
    /// systemd-boot is only updated when a newer version is available OR when the currently
    /// installed version is not signed. This enables switching to Lanzaboote without having to
    /// manually delete previous unsigned systemd-boot binaries and minimizes the number of writes
    /// to the ESP.
    ///
    /// Checking for the version also allows us to skip buggy systemd versions in the future.
    fn install_systemd_boot(&self) -> Result<()> {
        let systemd_boot = self
            .systemd
            .join("lib/systemd/boot/efi")
            .join(self.arch.systemd_filename());

        let paths = [
            (&systemd_boot, &self.esp_paths.efi_fallback),
            (&systemd_boot, &self.esp_paths.systemd_boot),
        ];

        for (from, to) in paths {
            let newer_systemd_boot_available = newer_systemd_boot(from, to)?;
            if newer_systemd_boot_available {
                log::info!("Updating {to:?}...")
            };
            let systemd_boot_is_signed = &self.signer.verify_path(to)?;
            if !systemd_boot_is_signed {
                log::warn!("${to:?} is not signed. Replacing it with a signed binary...")
            };

            if newer_systemd_boot_available || !systemd_boot_is_signed {
                install_signed(&self.signer, from, to)
                    .with_context(|| format!("Failed to install systemd-boot binary to: {to:?}"))?;
            }
        }

        install(
            &self.systemd_boot_loader_config,
            &self.esp_paths.systemd_boot_loader_config,
        )
        .with_context(|| {
            format!(
                "Failed to install systemd-boot loader.conf to {:?}",
                &self.esp_paths.systemd_boot_loader_config
            )
        })?;

        Ok(())
    }
}

/// Translate an EFI path to an absolute path on the mounted ESP.
fn resolve_efi_path(esp: &Path, efi_path: &[u8]) -> Result<PathBuf> {
    Ok(esp.join(std::str::from_utf8(&efi_path[1..])?.replace('\\', "/")))
}

/// Compute the file name to be used for the stub of a certain generation, signed with the given key.
///
/// The generated name is input-addressed by the toplevel corresponding to the generation and the public part of the signing key.
fn stub_name<S: Signer>(generation: &Generation, signer: &S) -> Result<PathBuf> {
    let bootspec = &generation.spec.bootspec.bootspec;
    let public_key = signer.get_public_key()?;
    let stub_inputs = [
        // Generation numbers can be reused if the latest generation was deleted.
        // To detect this, the stub path depends on the actual toplevel used.
        ("toplevel", bootspec.toplevel.0.as_os_str().as_bytes()),
        // If the key is rotated, the signed stubs must be re-generated.
        // So we make their path depend on the public key used for signature.
        ("public_key", &public_key),
    ];
    let stub_input_hash = Base32Unpadded::encode_string(&Sha256::digest(
        serde_json::to_string(&stub_inputs).unwrap(),
    ));
    if let Some(specialisation_name) = &generation.specialisation_name {
        Ok(PathBuf::from(format!(
            "nixos-generation-{}-specialisation-{}-{}.efi",
            generation, specialisation_name, stub_input_hash
        )))
    } else {
        Ok(PathBuf::from(format!(
            "nixos-generation-{}-{}.efi",
            generation, stub_input_hash
        )))
    }
}

/// Install a PE file. The PE gets signed in the process.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This is implemented as an atomic write. The file is first written to the destination with a
/// `.tmp` suffix and then renamed to its final name. This is atomic, because a rename is an atomic
/// operation on POSIX platforms.
fn install_signed(signer: &impl Signer, from: &Path, to: &Path) -> Result<()> {
    log::debug!("Signing and installing {to:?}...");
    let to_tmp = to.with_extension(".tmp");
    ensure_parent_dir(&to_tmp);
    signer
        .sign_and_copy(from, &to_tmp)
        .with_context(|| format!("Failed to copy and sign file from {from:?} to {to:?}"))?;
    fs::rename(&to_tmp, to).with_context(|| {
        format!("Failed to move temporary file {to_tmp:?} to final location {to:?}")
    })?;
    Ok(())
}

/// Install an arbitrary file.
///
/// The file is only copied if
///     (1) it doesn't exist at the destination or,
///     (2) the hash of the file at the destination does not match the hash of the source file.
fn install(from: &Path, to: &Path) -> Result<()> {
    if !to.exists() || file_hash(from)? != file_hash(to)? {
        force_install(from, to)?;
    }
    Ok(())
}

/// Forcibly install an arbitrary file.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This function is only designed to copy files to the ESP. It sets the permission bits of the
/// file at the destination to 0o755, the expected permissions for a vfat ESP. This is useful for
/// producing file systems trees which can then be converted to a file system image.
fn force_install(from: &Path, to: &Path) -> Result<()> {
    log::debug!("Installing {to:?}...");
    ensure_parent_dir(to);
    atomic_copy(from, to)?;
    set_permission_bits(to, 0o755)
        .with_context(|| format!("Failed to set permission bits to 0o755 on file: {to:?}"))?;
    Ok(())
}

fn assemble_kernel_cmdline(init: &Path, kernel_params: Vec<String>) -> Vec<String> {
    let init_string = String::from(
        init.to_str()
            .expect("Failed to convert init path to string"),
    );
    let mut kernel_cmdline: Vec<String> = vec![format!("init={}", init_string)];
    kernel_cmdline.extend(kernel_params);
    kernel_cmdline
}

/// Atomically copy a file.
///
/// First, the content is written to a temporary file (with a `.tmp` extension).
/// Then, this file is synced, to ensure its data and metadata are fully on disk before continuing.
/// In the last step, the temporary file is renamed to the final destination.
///
/// Due to the deficiencies of FAT32, it is possible for the filesystem to become corrupted after power loss.
/// It is not possible to fully defend against this situation, so this operation is not actually fully atomic.
/// However, in all other cases, the target file is either present with its correct content or not present at all.
fn atomic_copy(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension(".tmp");
    {
        let mut from_file =
            File::open(from).with_context(|| format!("Failed to read the source file {from:?}"))?;
        let mut tmp_file = File::create(&tmp)
            .with_context(|| format!("Failed to create the temporary file {tmp:?}"))?;
        std::io::copy(&mut from_file, &mut tmp_file).with_context(|| {
            format!("Failed to copy from {from:?} to the temporary file {tmp:?}")
        })?;
        tmp_file
            .sync_all()
            .with_context(|| format!("Failed to sync the temporary file {tmp:?}"))?;
    }
    fs::rename(&tmp, to)
        .with_context(|| format!("Failed to move temporary file {tmp:?} to target {to:?}"))
}

/// Set the octal permission bits of the specified file.
fn set_permission_bits(path: &Path, permission_bits: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("File {path:?} doesn't have any metadata"))?
        .permissions();
    perms.set_mode(permission_bits);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on {path:?}"))
}

// Ensures the parent directory of an arbitrary path exists
fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
}

/// Determine if a newer systemd-boot version is available.
///
/// "Newer" can mean
///   (1) no file exists at the destination,
///   (2) the file at the destination is malformed,
///   (3) a binary with a higher version is available.
fn newer_systemd_boot(from: &Path, to: &Path) -> Result<bool> {
    // If the file doesn't exists at the destination, it should be installed.
    if !to.exists() {
        return Ok(true);
    }

    // If the version from the source binary cannot be read, something is irrecoverably wrong.
    let from_version = SystemdVersion::from_systemd_boot_binary(from)
        .with_context(|| format!("Failed to read systemd-boot version from {from:?}."))?;

    // If the version cannot be read from the destination binary, it is malformed. It should be
    // forcibly reinstalled.
    let to_version = match SystemdVersion::from_systemd_boot_binary(to) {
        Ok(version) => version,
        _ => return Ok(true),
    };

    Ok(from_version > to_version)
}
