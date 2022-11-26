use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::install;

#[derive(Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Install {
        // Secure Boot Public Key
        #[clap(long)]
        public_key: PathBuf,

        // Secure Boot Private Key
        #[clap(long)]
        private_key: PathBuf,

        // Secure Boot PKI Bundle for auto enrolling key
        #[clap(long)]
        pki_bundle: Option<PathBuf>,

        // Enable auto enrolling your keys in UEFI
        // Be aware that this might irrevocably brick your device
        #[clap(long, default_value = "false")]
        auto_enroll: bool,

        bootspec: PathBuf,

        generations: Vec<PathBuf>,
    },
}

impl Cli {
    pub fn call(self) -> Result<()> {
        self.commands.call()
    }
}

impl Commands {
    pub fn call(self) -> Result<()> {
        match self {
            Commands::Install {
                public_key,
                private_key,
                pki_bundle,
                auto_enroll,
                bootspec,
                generations,
            } => install(
                &public_key,
                &private_key,
                &pki_bundle,
                auto_enroll,
                &bootspec,
                generations,
            ),
        }
    }
}

fn install(
    public_key: &Path,
    private_key: &Path,
    pki_bundle: &Option<PathBuf>,
    auto_enroll: bool,
    bootspec: &Path,
    generations: Vec<PathBuf>,
) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;
    let initrd_stub = std::env::var("LANZABOOTE_INITRD_STUB")
        .context("Failed to read LANZABOOTE_INITRD_STUB env variable")?;

    install::install(
        public_key,
        private_key,
        pki_bundle,
        auto_enroll,
        bootspec,
        generations,
        Path::new(&lanzaboote_stub),
        Path::new(&initrd_stub),
    )
}
