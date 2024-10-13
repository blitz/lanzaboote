use alloc::{collections::BTreeMap, string::ToString};
use log::info;
use uefi::{
    cstr16,
    proto::tcg::PcrIndex,
    table::{runtime::VariableAttributes, Boot, SystemTable},
    CString16,
};

use crate::{
    companions::{CompanionInitrd, CompanionInitrdType},
    efivars::BOOT_LOADER_VENDOR_UUID,
    pe_section::pe_section_data,
    tpm::tpm_log_event_ascii,
    uefi_helpers::PeInMemory,
    unified_sections::UnifiedSection,
};

/// This is where any stub payloads are extended, e.g. kernel ELF image, embedded initrd
/// and so on.
/// Compared to PCR4, this contains only the unified sections rather than the whole PE image as-is.
const TPM_PCR_INDEX_KERNEL_IMAGE: PcrIndex = PcrIndex(11);
/// This is where lanzastub extends the kernel command line and any passed credentials into
const TPM_PCR_INDEX_KERNEL_CONFIG: PcrIndex = PcrIndex(12);
/// This is where we extend the initrd sysext images into which we pass to the booted kernel
const TPM_PCR_INDEX_SYSEXTS: PcrIndex = PcrIndex(13);

pub fn measure_image(system_table: &SystemTable<Boot>, image: &PeInMemory) -> uefi::Result<u32> {
    let runtime_services = system_table.runtime_services();
    let boot_services = system_table.boot_services();

    // SAFETY: We get a slice that represents our currently running
    // image and then parse the PE data structures from it. This is
    // safe, because we don't touch any data in the data sections that
    // might conceivably change while we look at the slice.
    // (data sections := all unified sections that can be measured.)
    let pe_binary = unsafe { image.as_slice() };
    let pe = goblin::pe::PE::parse(pe_binary).map_err(|_err| uefi::Status::LOAD_ERROR)?;

    let mut measurements = 0;

    // Match behaviour of systemd-stub (see src/boot/efi/stub.c in systemd)
    // The encoding as well as the ordering of measurements is critical.
    //
    // References:
    //
    // "TPM2 PCR Measurements Made by systemd", https://systemd.io/TPM2_PCR_MEASUREMENTS/
    //   Section: PCR Measurements Made by systemd-stub (UEFI)
    //   - PCR 11, EV_IPL, “PE Section Name”
    //   - PCR 11, EV_IPL, “PE Section Data”
    //
    // Unified Kernel Image (UKI) specification, UAPI Group,
    // https://uapi-group.org/specifications/specs/unified_kernel_image/#uki-tpm-pcr-measurements
    //
    // Citing from "UKI TPM PCR Measurements":
    //   On systems with a Trusted Platform Module (TPM) the UEFI boot stub shall measure the sections listed above,
    //   starting from the .linux section, in the order as listed (which should be considered the canonical order).
    //   The .pcrsig section is not measured.
    //
    //   For each section two measurements shall be made into PCR 11 with the event code EV_IPL:
    //    - The section name in ASCII (including one trailing NUL byte)
    //    - The (binary) section contents
    //
    //   The above should be repeated for every section defined above, so that the measurements are interleaved:
    //   section name followed by section data, followed by the next section name and its section data, and so on.

    // NOTE: The order of measurements is important, so the use of BTreeMap is intentional here.
    let ordered_sections: BTreeMap<_, _> = pe
        .sections
        .iter()
        .filter_map(|section| {
            let section_name = section.name().ok()?;
            let unified_section = UnifiedSection::try_from(section_name).ok()?;
            unified_section
                .should_be_measured()
                .then_some((unified_section, section))
        })
        .collect();

    for (unified_section, section) in ordered_sections {
        let section_name = unified_section.name();

        info!("Measuring section `{}`...", section_name);

        // First measure the section name itself
        // This needs to be an UTF-8 encoded string with a trailing null byte
        //
        // As per reference:
        // "Measured hash covers the PE section name in ASCII (including a trailing NUL byte!)."
        let section_name_cstr_utf8 = unified_section.name_cstr();

        if tpm_log_event_ascii(
            boot_services,
            TPM_PCR_INDEX_KERNEL_IMAGE,
            section_name_cstr_utf8.as_bytes_with_nul(),
            section_name,
        )? {
            measurements += 1;
        }

        // Then measure the section contents.
        let Some(data) = pe_section_data(pe_binary, section) else {
            continue;
        };

        if tpm_log_event_ascii(
            boot_services,
            TPM_PCR_INDEX_KERNEL_IMAGE,
            data,
            section_name,
        )? {
            measurements += 1;
        }
    }

    if measurements > 0 {
        let pcr_index_encoded =
            CString16::try_from(TPM_PCR_INDEX_KERNEL_IMAGE.0.to_string().as_str())
                .map_err(|_err| uefi::Status::UNSUPPORTED)?;

        // If we did some measurements, expose a variable encoding the PCR where
        // we have done the measurements.
        runtime_services.set_variable(
            cstr16!("StubPcrKernelImage"),
            &BOOT_LOADER_VENDOR_UUID,
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
            pcr_index_encoded.as_bytes(),
        )?;
    }

    Ok(measurements)
}

/// Performs all the expected measurements for any list of
/// companion initrds of any form.
///
/// Relies on the passed order of `companions` for measurements in the same PCR.
/// A stable order is expected for measurement stability.
pub fn measure_companion_initrds(
    system_table: &SystemTable<Boot>,
    companions: &[CompanionInitrd],
) -> uefi::Result<u32> {
    let runtime_services = system_table.runtime_services();
    let boot_services = system_table.boot_services();

    let mut measurements = 0;
    let mut credentials_measured = 0;
    let mut sysext_measured = false;

    for initrd in companions {
        match initrd.r#type {
            CompanionInitrdType::PcrSignature | CompanionInitrdType::PcrPublicKey => {
                continue;
            }
            CompanionInitrdType::Credentials => {
                if tpm_log_event_ascii(
                    boot_services,
                    TPM_PCR_INDEX_KERNEL_CONFIG,
                    initrd.cpio.as_ref(),
                    "Credentials initrd",
                )? {
                    measurements += 1;
                    credentials_measured += 1;
                }
            }
            CompanionInitrdType::GlobalCredentials => {
                if tpm_log_event_ascii(
                    boot_services,
                    TPM_PCR_INDEX_KERNEL_CONFIG,
                    initrd.cpio.as_ref(),
                    "Global credentials initrd",
                )? {
                    measurements += 1;
                    credentials_measured += 1;
                }
            }
            CompanionInitrdType::SystemExtension => {
                if tpm_log_event_ascii(
                    boot_services,
                    TPM_PCR_INDEX_SYSEXTS,
                    initrd.cpio.as_ref(),
                    "System extension initrd",
                )? {
                    measurements += 1;
                    sysext_measured = true;
                }
            }
        }
    }

    if credentials_measured > 0 {
        runtime_services.set_variable(
            cstr16!("StubPcrKernelParameters"),
            &BOOT_LOADER_VENDOR_UUID,
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
            &TPM_PCR_INDEX_KERNEL_CONFIG.0.to_le_bytes(),
        )?;
    }

    if sysext_measured {
        runtime_services.set_variable(
            cstr16!("StubPcrInitRDSysExts"),
            &BOOT_LOADER_VENDOR_UUID,
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
            &TPM_PCR_INDEX_SYSEXTS.0.to_le_bytes(),
        )?;
    }

    Ok(measurements)
}
