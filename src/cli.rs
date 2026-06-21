use crate::config::PromptMethod;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "file-guard",
    about = "FUSE-based credential access control daemon"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the daemon (runs in the foreground; let systemd supervise it)
    Start {
        /// No-op: file-guard is supervised by systemd (Type=exec), not
        /// self-daemonizing. Kept for compatibility; use `systemctl` to manage.
        #[arg(short, long)]
        daemon: bool,
    },
    /// Run the user-session prompt agent. Renders access prompts (GUI/terminal)
    /// for the root daemon, which connects over a unix socket.
    Agent {
        /// Socket to listen on. Overrides FILE_GUARD_AGENT_SOCKET and the
        /// default; ignored under systemd socket activation.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// How to render prompts. Defaults to the config's prompt_method, else gui.
        #[arg(long, value_enum)]
        method: Option<PromptMethod>,
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
