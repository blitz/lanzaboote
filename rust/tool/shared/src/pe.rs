use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::utils::{file_hash, tmpname, SecureTempDirExt};

#[derive(Debug, Serialize, Deserialize)]
pub struct StubParameters {
    pub lanzaboote_store_path: PathBuf,
    pub kernel_cmdline: Vec<String>,
    pub os_release_contents: Vec<u8>,
    pub kernel_store_path: PathBuf,
    pub initrd_store_path: PathBuf,
    /// Kernel path rooted at the ESP
    /// i.e. if you refer to /boot/efi/EFI/NixOS/kernel.efi
    /// this gets turned into \\EFI\\NixOS\\kernel.efi as a UTF-16 string
    /// at assembling time.
    pub kernel_path_at_esp: String,
    /// Same as kernel.
    pub initrd_path_at_esp: String,
}

impl StubParameters {
    pub fn new(
        lanzaboote_stub: &Path,
        kernel_path: &Path,
        initrd_path: &Path,
        kernel_target: &Path,
        initrd_target: &Path,
        esp: &Path,
    ) -> Result<Self> {
        // Resolve maximally those paths
        // We won't verify they are store paths, otherwise the mocking strategy will fail for our
        // unit tests.

        Ok(Self {
            lanzaboote_store_path: lanzaboote_stub.to_path_buf(),
            kernel_store_path: kernel_path.to_path_buf(),
            initrd_store_path: initrd_path.to_path_buf(),
            kernel_path_at_esp: esp_relative_uefi_path(esp, kernel_target)?,
            initrd_path_at_esp: esp_relative_uefi_path(esp, initrd_target)?,
            kernel_cmdline: Vec::new(),
            os_release_contents: Vec::new(),
        })
    }

    pub fn with_os_release_contents(mut self, os_release_contents: &[u8]) -> Self {
        self.os_release_contents = os_release_contents.to_vec();
        self
    }

    pub fn with_cmdline(mut self, cmdline: &[String]) -> Self {
        self.kernel_cmdline = cmdline.to_vec();
        self
    }

    pub fn all_signables_in_store(&self) -> bool {
        self.lanzaboote_store_path.starts_with("/nix/store")
            && self.kernel_store_path.starts_with("/nix/store")
            && self.initrd_store_path.starts_with("/nix/store")
    }
}

/// Performs the evil operation
/// of calling the appender script to append
/// initrd "secrets" (not really) to the initrd.
pub fn append_initrd_secrets(
    append_initrd_secrets_path: &Path,
    initrd_path: &PathBuf,
    generation_version: u64,
) -> Result<()> {
    let status = Command::new(append_initrd_secrets_path)
        .args(vec![initrd_path])
        .status()
        .context("Failed to append initrd secrets")?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "Failed to append initrd secrets for generation {} with args `{:?}`",
            generation_version,
            vec![append_initrd_secrets_path, initrd_path]
        ));
    }

    Ok(())
}

/// Assemble a lanzaboote image.
pub fn lanzaboote_image(
    // Because the returned path of this function is inside the tempdir as well, the tempdir must
    // live longer than the function. This is why it cannot be created inside the function.
    tempdir: &TempDir,
    stub_parameters: &StubParameters,
) -> Result<PathBuf> {
    // objcopy can only copy files into the PE binary. That's why we
    // have to write the contents of some bootspec properties to disk.
    let kernel_cmdline_file =
        tempdir.write_secure_file(stub_parameters.kernel_cmdline.join(" "))?;

    let kernel_path_file = tempdir.write_secure_file(&stub_parameters.kernel_path_at_esp)?;
    let kernel_hash_file =
        tempdir.write_secure_file(file_hash(&stub_parameters.kernel_store_path)?.as_slice())?;

    let initrd_path_file = tempdir.write_secure_file(&stub_parameters.initrd_path_at_esp)?;
    let initrd_hash_file =
        tempdir.write_secure_file(file_hash(&stub_parameters.initrd_store_path)?.as_slice())?;

    let os_release = tempdir.write_secure_file(&stub_parameters.os_release_contents)?;
    let os_release_offs = stub_offset(&stub_parameters.lanzaboote_store_path)?;
    let kernel_cmdline_offs = os_release_offs + file_size(&os_release)?;
    let initrd_path_offs = kernel_cmdline_offs + file_size(&kernel_cmdline_file)?;
    let kernel_path_offs = initrd_path_offs + file_size(&initrd_path_file)?;
    let initrd_hash_offs = kernel_path_offs + file_size(&kernel_path_file)?;
    let kernel_hash_offs = initrd_hash_offs + file_size(&initrd_hash_file)?;

    let sections = vec![
        s(".osrel", os_release, os_release_offs),
        s(".cmdline", kernel_cmdline_file, kernel_cmdline_offs),
        s(".initrd", initrd_path_file, initrd_path_offs),
        s(".linux", kernel_path_file, kernel_path_offs),
        s(".initrdh", initrd_hash_file, initrd_hash_offs),
        s(".linuxh", kernel_hash_file, kernel_hash_offs),
    ];

    let image_path = tempdir.path().join(tmpname());
    wrap_in_pe(
        &stub_parameters.lanzaboote_store_path,
        sections,
        &image_path,
    )?;
    Ok(image_path)
}

/// Take a PE binary stub and attach sections to it.
///
/// The resulting binary is then written to a newly created file at the provided output path.
fn wrap_in_pe(stub: &Path, sections: Vec<Section>, output: &Path) -> Result<()> {
    let mut args: Vec<OsString> = sections.iter().flat_map(Section::to_objcopy).collect();

    [stub.as_os_str(), output.as_os_str()]
        .iter()
        .for_each(|a| args.push(a.into()));

    let status = Command::new("objcopy")
        .args(&args)
        .status()
        .context("Failed to run objcopy. Most likely, the binary is not on PATH.")?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "Failed to wrap in pe with args `{:?}`",
            &args
        ));
    }

    Ok(())
}

struct Section {
    name: &'static str,
    file_path: PathBuf,
    offset: u64,
}

impl Section {
    /// Create objcopy `-add-section` command line parameters that
    /// attach the section to a PE file.
    fn to_objcopy(&self) -> Vec<OsString> {
        // There is unfortunately no format! for OsString, so we cannot
        // just format a path.
        let mut map_str: OsString = format!("{}=", self.name).into();
        map_str.push(&self.file_path);

        vec![
            OsString::from("--add-section"),
            map_str,
            OsString::from("--change-section-vma"),
            format!("{}={:#x}", self.name, self.offset).into(),
        ]
    }
}

fn s(name: &'static str, file_path: impl AsRef<Path>, offset: u64) -> Section {
    Section {
        name,
        file_path: file_path.as_ref().into(),
        offset,
    }
}

/// Convert a path to an UEFI path relative to the specified ESP.
fn esp_relative_uefi_path(esp: &Path, path: &Path) -> Result<String> {
    let relative_path = path
        .strip_prefix(esp)
        .with_context(|| format!("Failed to strip esp prefix: {:?} from: {:?}", esp, path))?;
    let uefi_path = uefi_path(relative_path)?;
    Ok(format!("\\{}", &uefi_path))
}

/// Convert a path to a UEFI string representation.
///
/// This might not _necessarily_ produce a valid UEFI path, since some UEFI implementations might
/// not support UTF-8 strings. A Rust String, however, is _always_ valid UTF-8.
fn uefi_path(path: &Path) -> Result<String> {
    path.to_str()
        .to_owned()
        .map(|x| x.replace('/', "\\"))
        .with_context(|| format!("Failed to convert {:?} to an UEFI path", path))
}

fn stub_offset(binary: &Path) -> Result<u64> {
    let pe_binary = fs::read(binary).context("Failed to read PE binary file")?;
    let pe = PE::parse(&pe_binary).context("Failed to parse PE binary file")?;

    let image_base = image_base(&pe);

    // The Virtual Memory Address (VMA) is relative to the image base, aka the image base
    // needs to be added to the virtual address to get the actual (but still virtual address)
    Ok(u64::from(
        pe.sections
            .last()
            .map(|s| s.virtual_size + s.virtual_address)
            .expect("Failed to calculate offset"),
    ) + image_base)
}

fn image_base(pe: &PE) -> u64 {
    pe.header
        .optional_header
        .expect("Failed to find optional header, you're fucked")
        .windows_fields
        .image_base
}

fn file_size(path: impl AsRef<Path>) -> Result<u64> {
    Ok(fs::metadata(&path)
        .with_context(|| {
            format!(
                "Failed to read file metadata to calculate its size: {:?}",
                path.as_ref()
            )
        })?
        .size())
}

/// Read the data from a section of a PE binary.
///
/// The binary is supplied as a `u8` slice.
pub fn read_section_data<'a>(file_data: &'a [u8], section_name: &str) -> Option<&'a [u8]> {
    let pe_binary = goblin::pe::PE::parse(file_data).ok()?;

    pe_binary
        .sections
        .iter()
        .find(|s| s.name().unwrap() == section_name)
        .and_then(|s| {
            let section_start: usize = s.pointer_to_raw_data.try_into().ok()?;
            assert!(s.virtual_size <= s.size_of_raw_data);
            let section_end: usize = section_start + usize::try_from(s.virtual_size).ok()?;
            Some(&file_data[section_start..section_end])
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_to_valid_uefi_path_relative_to_esp() {
        let esp = Path::new("esp");
        let path = Path::new("esp/lanzaboote/is/great.txt");
        let converted_path = esp_relative_uefi_path(esp, path).unwrap();
        let expected_path = String::from("\\lanzaboote\\is\\great.txt");
        assert_eq!(converted_path, expected_path);
    }

    #[test]
    fn convert_to_valid_uefi_path() {
        let path = Path::new("lanzaboote/is/great.txt");
        let converted_path = uefi_path(path).unwrap();
        let expected_path = String::from("lanzaboote\\is\\great.txt");
        assert_eq!(converted_path, expected_path);
    }
}
