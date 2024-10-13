use alloc::ffi::CString;

/// List of PE sections that have a special meaning with respect to
/// UKI specification.
/// This is the canonical order in which they are measured into TPM
/// PCR 11.
/// !!! DO NOT REORDER !!!
#[derive(PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum UnifiedSection {
    Linux = 0,
    OsRel = 1,
    CmdLine = 2,
    Initrd = 3,
    Splash = 4,
    Dtb = 5,
    PcrSig = 6,
    PcrPkey = 7,
}

impl TryFrom<&str> for UnifiedSection {
    type Error = uefi::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            ".linux" => Self::Linux,
            ".osrel" => Self::OsRel,
            ".cmdline" => Self::CmdLine,
            ".initrd" => Self::Initrd,
            ".splash" => Self::Splash,
            ".dtb" => Self::Dtb,
            ".pcrsig" => Self::PcrSig,
            ".pcrpkey" => Self::PcrPkey,
            _ => return Err(uefi::Status::INVALID_PARAMETER.into()),
        })
    }
}

impl UnifiedSection {
    /// Whether this section should be measured into TPM.
    pub fn should_be_measured(&self) -> bool {
        !matches!(self, UnifiedSection::PcrSig)
    }

    /// The canonical section name.
    pub fn name(&self) -> &'static str {
        match self {
            UnifiedSection::Linux => ".linux",
            UnifiedSection::OsRel => ".osrel",
            UnifiedSection::CmdLine => ".cmdline",
            UnifiedSection::Initrd => ".initrd",
            UnifiedSection::Splash => ".splash",
            UnifiedSection::Dtb => ".dtb",
            UnifiedSection::PcrSig => ".pcrsig",
            UnifiedSection::PcrPkey => ".pcrpkey",
        }
    }

    /// The section name as a `CString`.
    pub fn name_cstr(&self) -> CString {
        // This should never panic:
        // CString::new() only returns an error on strings containing a null byte,
        // and we only call it on strings we specified above
        CString::new(self.name()).expect("section name should not contain a null byte")
    }
}
