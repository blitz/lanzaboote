use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use lanzaboote_tool::signature::local::LocalKeyPair;
use log::{info, trace};
use policy::TrivialPolicy;
use rouille::router;
use rouille::Response;

mod handlers;
mod policy;

use crate::handlers::Handlers;

#[derive(Parser)]
struct Cli {
    /// Verbose mode (-v, -vv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve(ServeCommand),
}

#[derive(Parser)]
struct ServeCommand {
    /// Port for the service
    #[arg(long)]
    port: u16,

    /// Policy file settings
    #[arg(long)]
    policy_file: PathBuf,

    /// sbsign Public Key
    #[arg(long)]
    public_key: PathBuf,

    /// sbsign Private Key
    #[arg(long)]
    private_key: PathBuf,
}

/// The default log level.
///
/// 2 corresponds to the level INFO.
const DEFAULT_LOG_LEVEL: usize = 2;

impl Cli {
    pub fn call(self, module: &str) {
        stderrlog::new()
            .module(module)
            .show_level(false)
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
            Commands::Serve(args) => serve(args),
        }
    }
}

fn serve(args: ServeCommand) -> Result<()> {
    let keypair = LocalKeyPair::new(&args.public_key, &args.private_key);
    let policy: TrivialPolicy = serde_json::from_slice(&std::fs::read(args.policy_file)?)?;
    let handlers = Handlers::new(keypair, policy);
    info!("Listening on 0.0.0.0:{}", args.port);
    rouille::start_server(format!("0.0.0.0:{}", args.port), move |request| {
        trace!("Receiving {:#?}", request);
        router!(request,
            (POST) (/sign-stub) => {
                handlers.sign_stub(request)
            },
            (POST) (/sign-store-path) => {
                handlers.sign_store_path(request)
            },
            (POST) (/verify) => {
                handlers.verify(request)
            },
            _ => {
                Response::text("lanzasignd signature endpoint")
            }
        )
    });
}

fn main() {
    Cli::parse().call(module_path!())
}
