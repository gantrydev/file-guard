mod cli;
mod commands;
mod config;
mod config_runtime;
mod control;
mod control_api;
mod daemon;
mod interceptor;
mod logging;
mod policy;
mod process;
mod prompt;
mod rule_store;
mod secure_file;
mod store;
#[cfg(test)]
mod testing;
mod transaction;

#[cfg(target_os = "linux")]
mod fuse_fs;

use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    commands::execute(cli.command).await
}
