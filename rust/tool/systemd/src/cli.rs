use std::{path::PathBuf, io::Write};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tempfile::TempDir;

use crate::install;
use lanzaboote_tool::architecture::Architecture;
use lanzaboote_tool::signature::KeyPair;
use lanzaboote_tool::generation::{GenerationLink, Generation}, pe, os_release::OsRelease, utils::{SecureTempDirExt, assemble_kernel_cmdline}, esp::{EspGenerationPaths, BuildEspPaths, EspPaths}};

/// The default log level.
///
/// 2 corresponds to the level INFO.
const DEFAULT_LOG_LEVEL: usize = 2;

#[derive(Parser)]
pub struct Cli {
    /// Silence all output
    #[arg(short, long)]
    quiet: bool,
    /// Verbose mode (-v, -vv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install(InstallCommand),
    Build(BuildCommand)
}

#[derive(Parser)]
struct BuildCommand {
    /// sbsign Public Key
    #[arg(long)]
    public_key: PathBuf,

    /// sbsign Private Key
    #[arg(long)]
    private_key: PathBuf,

    /// Override initrd
    #[arg(long)]
    initrd: PathBuf,

    /// Generation
    generation: PathBuf
}

#[derive(Parser)]
struct InstallCommand {
    /// System for lanzaboote binaries, e.g. defines the EFI fallback path
    #[arg(long)]
    system: String,

    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// Systemd-boot loader config
    #[arg(long)]
    systemd_boot_loader_config: PathBuf,

    /// sbsign Public Key
    #[arg(long)]
    public_key: PathBuf,

    /// sbsign Private Key
    #[arg(long)]
    private_key: PathBuf,

    /// Configuration limit
    #[arg(long, default_value_t = 1)]
    configuration_limit: usize,

    /// EFI system partition mountpoint (e.g. efiSysMountPoint)
    esp: PathBuf,

    /// List of generation links (e.g. /nix/var/nix/profiles/system-*-link)
    generations: Vec<PathBuf>,
}

impl Cli {
    pub fn call(self, module: &str) {
        stderrlog::new()
            .module(module)
            .show_level(false)
            .quiet(self.quiet)
            .verbosity(DEFAULT_LOG_LEVEL + usize::from(self.verbose))
            .init()
            .expect("Failed to setup logger.");

        if let Err(e) = self.commands.call() {
            log::error!("{e:#}");
            std::process::exit(1);
        };
    }
}

impl Commands {
    pub fn call(self) -> Result<()> {
        match self {
            Commands::Install(args) => install(args),
            Commands::Build(args) => build(args),
        }
    }
}

fn install(args: InstallCommand) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;

    let key_pair = KeyPair::new(&args.public_key, &args.private_key);

    install::Installer::new(
        PathBuf::from(lanzaboote_stub),
        Architecture::from_nixos_system(&args.system)?,
        args.systemd,
        args.systemd_boot_loader_config,
        key_pair,
        args.configuration_limit,
        args.esp,
        args.generations,
    )
    .install()
}

fn build(args: BuildCommand) -> Result<()> {
    let lanzaboote_stub =
        PathBuf::from(std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?);

    let key_pair = KeyPair::new(&args.public_key, &args.private_key);

    let generation = Generation::from_toplevel(&args.generation, 1)
        .with_context(|| format!("Failed to build generation from link: {0:?}", args.generation))?;
    let bootspec = &generation.spec.bootspec.bootspec;

    let tempdir = TempDir::new().context("Failed to create temporary directory")?;
    let os_release = OsRelease::from_generation(&generation)
        .context("Failed to build OsRelease from generation.")?;
    let os_release_path = tempdir
        .write_secure_file(os_release.to_string().as_bytes())
        .context("Failed to write os-release file.")?;
    let kernel_cmdline =
        assemble_kernel_cmdline(&bootspec.init, bootspec.kernel_params.clone());
    let esp = PathBuf::from("/");
    let esp_paths = BuildEspPaths::new("/");
    let esp_gen_paths = EspGenerationPaths::new(&esp_paths, &generation)?;

    let lzbt_stub = pe::lanzaboote_image(
        &tempdir,
        &lanzaboote_stub,
        &os_release_path,
        &kernel_cmdline,
        &bootspec.kernel,
        &args.initrd,
        &esp_gen_paths,
        &esp
    )?;

    // Sign the stub.
    let to = tempdir.path().join("signed-lzbt-stub.efi");
    key_pair
        .sign_and_copy(&lzbt_stub, &to)
        .with_context(|| format!("Failed to copy and sign file {lzbt_stub:?} to {to:?}"))?;

    // Output the stub on stdout.
    std::io::stdout().write_all(&std::fs::read(to)?)?;

    Ok(())
}
