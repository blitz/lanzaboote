use anyhow::Result;
use base32ct::{Base32Unpadded, Encoding};
use tempfile::tempdir;

mod common;

use common::{
    count_files, hash_file, remove_signature, setup_generation_link_from_toplevel, verify_signature,
};

/// Install two generations that point at the same toplevel.
/// This should install two lanzaboote images and one kernel and one initrd.
#[test]
fn do_not_install_duplicates() -> Result<()> {
    let esp = tempdir()?;
    let tmpdir = tempdir()?;
    let profiles = tempdir()?;
    let toplevel = common::setup_toplevel(tmpdir.path())?;

    let generation_link1 = setup_generation_link_from_toplevel(&toplevel, profiles.path(), 1)?;
    let generation_link2 = setup_generation_link_from_toplevel(&toplevel, profiles.path(), 2)?;
    let generation_links = vec![generation_link1, generation_link2];

    let stub_count = || count_files(&esp.path().join("EFI/Linux")).unwrap();
    let kernel_and_initrd_count = || count_files(&esp.path().join("EFI/nixos")).unwrap();

    let output1 = common::lanzaboote_install(0, esp.path(), generation_links)?;
    assert!(output1.status.success());
    assert_eq!(stub_count(), 2, "Wrong number of stubs after installation");
    assert_eq!(
        kernel_and_initrd_count(),
        2,
        "Wrong number of kernels & initrds after installation"
    );
    Ok(())
}

#[test]
fn do_not_overwrite_images() -> Result<()> {
    let esp = tempdir()?;
    let tmpdir = tempdir()?;
    let profiles = tempdir()?;
    let toplevel = common::setup_toplevel(tmpdir.path())?;

    let image1 = common::image_path(&esp, 1, &toplevel)?;
    let image2 = common::image_path(&esp, 2, &toplevel)?;

    let generation_link1 = setup_generation_link_from_toplevel(&toplevel, profiles.path(), 1)?;
    let generation_link2 = setup_generation_link_from_toplevel(&toplevel, profiles.path(), 2)?;
    let generation_links = vec![generation_link1, generation_link2];

    let output1 = common::lanzaboote_install(0, esp.path(), generation_links.clone())?;
    assert!(output1.status.success());

    assert!(verify_signature(&image1)?);
    remove_signature(&image1)?;
    assert!(!verify_signature(&image1)?);
    assert!(verify_signature(&image2)?);

    let output2 = common::lanzaboote_install(0, esp.path(), generation_links)?;
    assert!(output2.status.success());

    assert!(!verify_signature(&image1)?);
    assert!(verify_signature(&image2)?);

    Ok(())
}

#[test]
fn detect_generation_number_reuse() -> Result<()> {
    let esp = tempdir()?;
    let tmpdir = tempdir()?;
    let profiles = tempdir()?;
    let toplevel1 = common::setup_toplevel(tmpdir.path())?;
    let toplevel2 = common::setup_toplevel(tmpdir.path())?;

    let image1 = common::image_path(&esp, 1, &toplevel1)?;
    // this deliberately gets the same number!
    let image2 = common::image_path(&esp, 1, &toplevel2)?;

    let generation_link1 = setup_generation_link_from_toplevel(&toplevel1, profiles.path(), 1)?;
    let output1 = common::lanzaboote_install(0, esp.path(), vec![generation_link1])?;
    assert!(output1.status.success());
    assert!(image1.exists());
    assert!(!image2.exists());

    std::fs::remove_dir_all(profiles.path().join("system-1-link"))?;
    let generation_link2 = setup_generation_link_from_toplevel(&toplevel2, profiles.path(), 1)?;
    let output2 = common::lanzaboote_install(0, esp.path(), vec![generation_link2])?;
    assert!(output2.status.success());
    assert!(!image1.exists());
    assert!(image2.exists());

    Ok(())
}

#[test]
fn content_addressing_works() -> Result<()> {
    let esp = tempdir()?;
    let tmpdir = tempdir()?;
    let profiles = tempdir()?;
    let toplevel = common::setup_toplevel(tmpdir.path())?;

    let generation_link = setup_generation_link_from_toplevel(&toplevel, profiles.path(), 1)?;
    let generation_links = vec![generation_link];

    let kernel_hash_source =
        hash_file(&toplevel.join("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-6.1.1/kernel"));

    let output0 = common::lanzaboote_install(1, esp.path(), generation_links)?;
    assert!(output0.status.success());

    let kernel_path = esp.path().join(format!(
        "EFI/nixos/kernel-6.1.1-{}.efi",
        Base32Unpadded::encode_string(&kernel_hash_source)
    ));

    // Implicitly assert that the content-addressed file actually exists.
    let kernel_hash = hash_file(&kernel_path);
    // Assert the written kernel is the source kernel.
    assert_eq!(kernel_hash_source, kernel_hash);

    Ok(())
}
