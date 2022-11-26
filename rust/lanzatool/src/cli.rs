use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::install;
use crate::signature::KeyPair;

#[derive(Parser)]
pub struct Cli {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install(InstallCommand),
}

#[derive(Parser)]
struct InstallCommand {
    /// sbsign Public Key
    #[arg(long)]
    public_key: PathBuf,

    /// sbsign Private Key
    #[arg(long)]
    private_key: PathBuf,

    /// sbctl PKI bundle for auto enrolling key
    #[arg(long)]
    pki_bundle: Option<PathBuf>,

    /// Auto enroll your keys. This might brick your device
    #[arg(long, default_value = "false")]
    auto_enroll: bool,

    /// EFI system partition mountpoint (e.g. efiSysMountPoint)
    esp: PathBuf,

    /// List of generations (e.g. /nix/var/nix/profiles/system-*-link)
    generations: Vec<PathBuf>,
}

impl Cli {
    pub fn call(self) -> Result<()> {
        self.commands.call()
    }
}

impl Commands {
    pub fn call(self) -> Result<()> {
        match self {
            Commands::Install(args) => install(args),
        }
    }
}

fn install(args: InstallCommand) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;
    let initrd_stub = std::env::var("LANZABOOTE_INITRD_STUB")
        .context("Failed to read LANZABOOTE_INITRD_STUB env variable")?;

    let key_pair = KeyPair::new(&args.public_key, &args.private_key);

    install::Installer::new(
        PathBuf::from(lanzaboote_stub),
        PathBuf::from(initrd_stub),
        key_pair,
        args.pki_bundle,
        args.auto_enroll,
        args.esp,
        args.generations,
    )
    .install()
}
