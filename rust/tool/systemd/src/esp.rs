use std::path::{Path, PathBuf};

use crate::architecture::SystemdArchitectureExt;
use lanzaboote_tool::architecture::Architecture;
use lanzaboote_tool::esp::EspPaths;

/// Paths to the boot files that are not specific to a generation.
/// Systemd variant
pub struct SystemdEspPaths {
    pub esp: PathBuf,
    pub efi: PathBuf,
    pub nixos: PathBuf,
    pub linux: PathBuf,
    pub efi_fallback_dir: PathBuf,
    pub efi_fallback: PathBuf,
    pub systemd: PathBuf,
    pub systemd_boot: PathBuf,
    pub loader: PathBuf,
    pub entries: PathBuf,
    pub systemd_boot_loader_config: PathBuf,
}

impl EspPaths<11> for SystemdEspPaths {
    fn new(esp: impl AsRef<Path>, architecture: Architecture) -> Self {
        let esp = esp.as_ref();
        let efi = esp.join("EFI");
        let efi_nixos = efi.join("nixos");
        let efi_linux = efi.join("Linux");
        let efi_systemd = efi.join("systemd");
        let efi_efi_fallback_dir = efi.join("BOOT");
        let loader = esp.join("loader");
        let entries = loader.join("entries");
        let systemd_boot_loader_config = loader.join("loader.conf");

        Self {
            esp: esp.to_path_buf(),
            efi,
            nixos: efi_nixos,
            linux: efi_linux,
            efi_fallback_dir: efi_efi_fallback_dir.clone(),
            efi_fallback: efi_efi_fallback_dir.join(architecture.efi_fallback_filename()),
            systemd: efi_systemd.clone(),
            systemd_boot: efi_systemd.join(architecture.systemd_filename()),
            loader,
            entries,
            systemd_boot_loader_config,
        }
    }

    fn nixos_path(&self) -> &Path {
        &self.nixos
    }

    fn linux_path(&self) -> &Path {
        &self.linux
    }

    fn iter(&self) -> std::array::IntoIter<&PathBuf, 11> {
        [
            &self.esp,
            &self.efi,
            &self.nixos,
            &self.linux,
            &self.efi_fallback_dir,
            &self.efi_fallback,
            &self.systemd,
            &self.systemd_boot,
            &self.loader,
            &self.entries,
            &self.systemd_boot_loader_config,
        ]
        .into_iter()
    }
}
