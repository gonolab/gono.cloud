//! `gono-cloud`: command line entry point of Gono Cloud.

mod admin;
mod app;
mod auth;
mod cli;
mod client_ip;
mod commands;
mod connect;
mod direct;
mod files;
mod i18n;
mod janitor;
mod logging;
mod login_flow;
mod nextcloud;
mod notify_push;
mod password_input;
mod qr;
mod ratelimit;
mod request_log;
mod s3;
mod shutdown;
mod site;
mod web;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, ConfigCommand};

/// The static Linux release builds use musl, whose allocator serializes on a global lock and
/// slows down the many concurrent requests of a file server. mimalloc replaces it there; other
/// builds keep the system allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = cli.config.as_path();
    match cli.command {
        Command::Serve => commands::serve::run(config).await,
        Command::Relay => commands::relay::run(config).await,
        Command::Init(args) => commands::init::run(config, args).await,
        Command::Config(ConfigCommand::Check) => commands::config_check::run(config),
        Command::User(command) => commands::user::run(config, command).await,
        Command::AppPassword(command) => commands::app_password::run(config, command).await,
        Command::Device(command) => commands::device::run(config, command).await,
        Command::S3(command) => commands::s3::run(config, command).await,
        Command::Rescan(args) => commands::rescan::run(config, args).await,
    }
}
