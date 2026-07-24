#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Parser, Subcommand};
use orbit_core::GroupId;
use orbit_daemon::{DaemonError, InitializationOptions, Runtime, initialize, run_daemon, run_once};

#[derive(Debug, Parser)]
#[command(
    name = "orbit-daemon",
    version,
    about = "Encrypted peer-to-peer folder synchronization"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a node configuration and non-overwriting secret files.
    Init {
        #[arg(long, default_value = "orbit.toml")]
        config: PathBuf,
        #[arg(long)]
        sync_root: PathBuf,
        #[arg(long)]
        store_root: PathBuf,
        #[arg(long, default_value = "0.0.0.0:48177")]
        listen: SocketAddr,
        #[arg(long, requires = "group_secret_file")]
        group_id: Option<GroupId>,
        #[arg(long, requires = "group_id")]
        group_secret_file: Option<PathBuf>,
    },
    /// Run continuously until Ctrl-C or a service manager stops the process.
    Run {
        #[arg(long, default_value = "orbit.toml")]
        config: PathBuf,
    },
    /// Recover, materialize, scan, and pull each configured peer once.
    Once {
        #[arg(long, default_value = "orbit.toml")]
        config: PathBuf,
    },
    /// Print non-secret device, workspace, listener, and peer status.
    Status {
        #[arg(long, default_value = "orbit.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("orbit-daemon: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), DaemonError> {
    match cli.command {
        Command::Init {
            config,
            sync_root,
            store_root,
            listen,
            group_id,
            group_secret_file,
        } => {
            let initialized = initialize(&InitializationOptions {
                config_path: config,
                sync_root,
                store_root,
                listen_address: listen,
                group_id,
                group_secret_file,
            })?;
            println!("configuration: {}", initialized.config_path.display());
            println!("group ID: {}", initialized.group_id);
            println!("device ID: {}", initialized.device_id);
            println!("public key: {}", initialized.public_key_hex);
            Ok(())
        }
        Command::Run { config } => run_daemon(Arc::new(Runtime::load(config)?)).await,
        Command::Once { config } => run_once(Arc::new(Runtime::load(config)?)).await,
        Command::Status { config } => {
            let status = Runtime::load(config)?.status()?;
            println!("device ID: {}", status.device_id);
            println!("public key: {}", status.public_key);
            println!("group ID: {}", status.group_id);
            println!("listen address: {}", status.listen_address);
            println!("peers: {}", status.peers.len());
            Ok(())
        }
    }
}
