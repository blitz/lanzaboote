use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use lanzaboote_tool::pe::StubParameters;
use log::trace;
use serde::{Deserialize, Serialize};

pub trait Policy {
    /// Validate if this store path is trusted for signature.
    fn trusted_store_path(&self, store_path: &Path) -> bool;
    /// Validate if these stub parameters are trusted for signature.
    fn trusted_stub_parameters(&self, parameters: &StubParameters) -> bool;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrivialPolicy {
    pub allowed_kernel_cmdline_items: Option<HashSet<String>>,
    pub store_location: PathBuf,
}

impl Policy for TrivialPolicy {
    /// For now, we will only assume it does exist in our local store.
    /// This scenario makes sense if you deploy all your closures via this local machine's store,
    /// e.g. a big builder, NFS nix store, etc.
    fn trusted_store_path(&self, store_path: &Path) -> bool {
        trace!(
            "trusted store path {} → {}",
            store_path.display(),
            store_path.exists()
        );
        store_path.starts_with(&self.store_location) && store_path.exists()
    }

    fn trusted_stub_parameters(&self, parameters: &StubParameters) -> bool {
        if !self.trusted_store_path(&parameters.lanzaboote_store_path)
            || !self.trusted_store_path(&parameters.kernel_store_path)
            || !self.trusted_store_path(&parameters.initrd_store_path)
        {
            return false;
        }

        if let Some(allowed_cmdline_items) = &self.allowed_kernel_cmdline_items {
            for item in &parameters.kernel_cmdline {
                if !allowed_cmdline_items.contains(item) {
                    trace!("untrusted command line item: {item}");
                    return false;
                }
            }
        }

        // XXX: validate os_release_contents
        // parse then check if it contains allowed stuff?

        // kernel/initrd paths doesn't need to be validated per se.
        // let's assume they are manipulated, let be K the kernel path in ESP.
        // if the stub loads K, we will validate that hash(K) = hash in the stub.
        // because of how the stub works, if hash(K) = hash in the stub and the hash function
        // is strong enough, we know that K's contents = the kernel's contents we expected.
        // Therefore, integrity is ensured.
        // The only concern is that user could overwrite his bootables with the wrong K.
        // Is that a concern for this signing server? Not really.

        true
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lanzaboote_tool::pe::StubParameters;

    use super::{Policy, TrivialPolicy};

    #[test]
    fn test_reject_non_store_path() {
        let policy = TrivialPolicy {
            allowed_kernel_cmdline_items: None,
        };

        assert!(!policy.trusted_stub_parameters(
            &StubParameters::new(
                Path::new("/not/a/store/stub"),
                Path::new("/not/a/store/kernel"),
                Path::new("/not/a/store/initrd"),
                Path::new("/efi/kernel"),
                Path::new("/efi/initrd"),
                Path::new("/efi"),
            )
            .expect("Failed to obtain fake stub parameters"),
        ));
    }

    #[test]
    fn test_reject_non_existent_store_path() {
        let policy = TrivialPolicy {
            allowed_kernel_cmdline_items: None,
        };

        assert!(!policy.trusted_stub_parameters(
            &StubParameters::new(
                Path::new("/nix/store/stub"),
                Path::new("/nix/store/kernel"),
                Path::new("/nix/store/initrd"),
                Path::new("/efi/kernel"),
                Path::new("/efi/initrd"),
                Path::new("/efi"),
            )
            .expect("Failed to obtain fake stub parameters"),
        ));
    }
}
