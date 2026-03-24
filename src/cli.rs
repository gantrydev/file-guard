use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cred-guard", about = "FUSE-based credential access control daemon")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the daemon
    Start {
        /// Run as background daemon (via launchd/systemd)
        #[arg(short, long)]
        daemon: bool,
    },
    /// Stop the daemon, unmount all FUSE mounts
    Stop,
    /// Show watched files, mount state, recent access
    Status,
    /// Tail the access log
    Log,
    /// Manage access rules
    Rules {
        #[command(subcommand)]
        action: Option<RulesAction>,
    },
    /// Move a credential file into the backing store
    Store { file: PathBuf },
    /// Restore a file from the backing store to disk
    Restore { file: PathBuf },
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// Add a rule interactively
    Add,
    /// Remove a rule
    Remove,
}
