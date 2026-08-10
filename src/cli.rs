use crate::config::PromptMethod;
use crate::policy::rule::Access;
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
        /// No-op: file-guard is supervised by systemd (Type=notify), not
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
        /// Send a desktop notification alongside each prompt
        #[arg(long)]
        notify: bool,
    },
    /// Stop the running daemon (SIGTERM; unmounts all FUSE mounts)
    Stop,
    /// Show daemon state, watched files, mount status, and recent access
    Status,
    /// Print (and optionally follow) the structured audit log
    Log {
        /// Number of trailing entries to print
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Keep printing new entries as they are appended
        #[arg(short, long)]
        follow: bool,
    },
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
    /// Add a persistent rule. The binary is pinned by its current sha256 so a
    /// later change re-prompts (pass --no-pin to match on path alone).
    Add {
        /// Watched file the rule applies to (e.g. ~/.aws/credentials)
        #[arg(long)]
        file: String,
        /// Absolute path of the binary to authorize
        #[arg(long)]
        binary: PathBuf,
        /// Allow or deny
        #[arg(long, value_enum)]
        action: RuleAction,
        /// Direction the rule covers
        #[arg(long, value_enum, default_value_t = Access::Any)]
        access: Access,
        /// Don't pin the binary's hash (match on path only)
        #[arg(long)]
        no_pin: bool,
    },
    /// Remove the rule at INDEX (as shown by `file-guard rules`)
    Remove { index: usize },
    /// Edit an existing rule at INDEX: change action, access, or pinning.
    /// Unchanged fields keep their current values.
    Edit {
        /// Index of the rule to edit (as shown by `file-guard rules`)
        index: usize,
        /// Change action (allow / deny)
        #[arg(long, value_enum)]
        action: Option<RuleAction>,
        /// Change access direction
        #[arg(long, value_enum)]
        access: Option<Access>,
        /// Pin a new sha256 for the binary (re-hashes the current binary)
        #[arg(long, conflicts_with = "no_pin")]
        repin: bool,
        /// Drop the binary pin (match on path only)
        #[arg(long)]
        no_pin: bool,
    },
    /// List rules matching one or more filters
    Find {
        /// Filter by watched file path (substring match)
        #[arg(long)]
        file: Option<String>,
        /// Filter by binary path (substring match)
        #[arg(long)]
        binary: Option<String>,
        /// Filter by action
        #[arg(long, value_enum)]
        action: Option<RuleAction>,
    },
    /// Export all rules as TOML to stdout (portable format)
    Export,
    /// Import rules from TOML on stdin. Duplicates are skipped; existing
    /// rules are preserved. Reads until EOF.
    Import,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum RuleAction {
    Allow,
    Deny,
}
