use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use goblin::pe::section_table::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ};
use serde::{Deserialize, Serialize};

use crate::utils::file_hash;

/// Stub parameters is the sufficient
/// data to produce a "partial kernel image",
/// i.e. something like a unified kernel image (UKIs) but
/// which contains only references to the kernel, the initrd and more.
/// This is the trick that lanzaboote devised to avoid paying a UKI penalty
/// for each NixOS generation in the UKI model.
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

    /// Assemble into a final PE image
    /// this stub.
    pub fn into_image(&self) -> Result<Vec<u8>> {
        let initrd_hash = file_hash(&self.initrd_store_path)?;
        let kernel_hash = file_hash(&self.kernel_store_path)?;
        let final_kernel_cmdline = self.kernel_cmdline.join(" ");

        let sections = vec![
            s(".osrel", &self.os_release_contents)?,
            s(".cmdline", final_kernel_cmdline.as_bytes())?,
            s(".initrdp", self.initrd_path_at_esp.as_bytes())?,
            s(".kernelp", self.kernel_path_at_esp.as_bytes())?,
            s(".initrdh", initrd_hash.as_slice())?,
            s(".kernelh", kernel_hash.as_slice())?,
        ];

        let template_pe_data = std::fs::read(&self.lanzaboote_store_path)?;
        let template_pe = goblin::pe::PE::parse(&template_pe_data)?;

        let mut pe_writer = goblin::pe::writer::PEWriter::new(template_pe)?;

        for section in sections {
            pe_writer.insert_section(section)?;
        }

        Ok(pe_writer.write_into()?)
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

/// Data-only section.
#[inline]
fn s<'a>(name: &str, contents: &'a [u8]) -> anyhow::Result<goblin::pe::section_table::Section<'a>> {
    use goblin::pe::section_table::Section;

    // This is infallible (upstream), this might be my fault.
    let mut section_name = [0u8; 8];
    section_name[..name.len()].copy_from_slice(name.as_bytes());
    Ok(Section::new(
        &section_name,
        Some(contents.into()),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
    )
    .unwrap())
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
