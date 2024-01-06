use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::install;
use lanzaboote_tool::{
    architecture::Architecture,
    signature::{local::LocalKeyPair, remote::RemoteSigningServer, LanzabooteSigner},
};

/// The default log level.
///
/// 2 corresponds to the level INFO.
const DEFAULT_LOG_LEVEL: usize = 2;
/// Lanzaboote user agent
pub static USER_AGENT: &str = concat!(
    "lanzaboote tool (backend: systemd, version: ",
    env!("CARGO_PKG_VERSION"),
    ")"
);

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
}

#[derive(Parser)]
#[command(group = clap::ArgGroup::new("local-keys").multiple(true).requires_all(["private_key", "public_key"]).conflicts_with("remote_signing_server_url"))]
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
    #[arg(long, group = "local-keys")]
    public_key: Option<PathBuf>,

    /// sbsign Private Key
    #[arg(long, group = "local-keys")]
    private_key: Option<PathBuf>,

    /// Remote signing server
    #[arg(long)]
    remote_signing_server_url: Option<String>,

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
        }
    }
}

fn install_with_signer<S: LanzabooteSigner>(args: InstallCommand, signer: S) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;

    install::Installer::new(
        PathBuf::from(lanzaboote_stub),
        Architecture::from_nixos_system(&args.system)?,
        args.systemd,
        args.systemd_boot_loader_config,
        signer,
        args.configuration_limit,
        args.esp,
        args.generations,
    )
    .install()
}

fn install(args: InstallCommand) -> Result<()> {
    // Many bail are impossible because of Clap ensuring they don't happen.
    // For completeness, we provide them.
    if let Some(public_key) = &args.public_key {
        if let Some(private_key) = &args.private_key {
            let signer = LocalKeyPair::new(public_key, private_key);
            install_with_signer(args, signer)
        } else {
            bail!("Missing private key for local signature scheme!");
        }
    } else if let Some(_private_key) = &args.private_key {
        bail!("Missing public key for local signature scheme!");
    } else if let Some(remote_signing_server_url) = &args.remote_signing_server_url {
        let signer = RemoteSigningServer::new(remote_signing_server_url, USER_AGENT)
            .expect("Failed to create a remote signing server");
        install_with_signer(args, signer)
    } else {
        bail!("No mechanism for signature was provided, pass either a local pair of keys or a remote signing server");
    }
}
