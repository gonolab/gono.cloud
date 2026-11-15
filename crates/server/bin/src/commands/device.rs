//! `gono-cloud device ...`: the devices registered for remote access
//! (`docs/connect-protocol.md`, sections 6 and 9).
//!
//! Revocation here writes to the database only; a running server reads the event log and
//! the directory again within seconds, closes the device's control channel, disconnects it
//! from the relay and tells the account's other devices.

use std::{
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::Path,
};

use anyhow::{Context, bail};
use gono_server_core::{
    db,
    devices::{self, EndpointId, RevokedBy},
    users,
};

use super::{
    open_database,
    output::{format_optional_time, format_time, print_table},
};
use crate::cli::DeviceCommand;

/// Runs one `device` subcommand.
pub async fn run(config_path: &Path, command: DeviceCommand) -> anyhow::Result<()> {
    let (_, pool) = open_database(config_path).await?;
    let result = async {
        match command {
            DeviceCommand::List { username } => {
                let user = users::get(&pool, &username).await?;
                let rows: Vec<Vec<String>> = devices::list(&pool, user.id)
                    .await?
                    .into_iter()
                    .map(|device| {
                        vec![
                            device.endpoint_id.to_hex(),
                            device.name,
                            format!("{} on {}", device.product, device.platform),
                            format_time(device.registered_at),
                            format_optional_time(device.last_seen_at, "never"),
                            format_optional_time(device.left_at, "-"),
                            format_optional_time(device.revoked_at, "-"),
                        ]
                    })
                    .collect();
                print_table(
                    &[
                        "ENDPOINT ID",
                        "NAME",
                        "PRODUCT",
                        "REGISTERED",
                        "LAST SEEN",
                        "SIGNED OUT",
                        "REVOKED",
                    ],
                    &rows,
                );
                Ok(())
            }
            DeviceCommand::Revoke {
                username,
                endpoint_id,
                confirm,
            } => {
                let user = users::get(&pool, &username).await?;
                let key = EndpointId::parse(&endpoint_id.to_ascii_lowercase())
                    .context("the endpoint ID is 64 hex digits, as `device list` shows it")?;
                let Some(device) = devices::find(&pool, key)
                    .await?
                    .filter(|device| device.user_id == user.id)
                else {
                    bail!("{username} has no device {endpoint_id}");
                };
                if device.is_revoked() {
                    println!("{} ({}) is revoked already.", device.name, key.short());
                    return Ok(());
                }
                let introduced = devices::introduced_by(&pool, device.id).await?;
                println!(
                    "Revoking {} ({} on {}, {}) for good: its key can never be registered again, \
                     and {username}'s other devices forget it, on the local network as well.",
                    device.name,
                    device.product,
                    device.platform,
                    key.short()
                );
                if !introduced.is_empty() {
                    println!("It approved these devices, which stay trusted:");
                    for other in &introduced {
                        println!("  {}  {}", other.endpoint_id.to_hex(), other.name);
                    }
                    println!("Revoke them as well if they should not be.");
                }
                confirmed(&key, confirm.as_deref())?;
                let revoked =
                    devices::revoke(&pool, user.id, &[key], RevokedBy::Cli, None, db::unix_now())
                        .await?;
                if revoked.is_empty() {
                    println!("Nothing to revoke: the device changed in the meantime.");
                } else {
                    println!("Revoked {}.", device.name);
                }
                Ok(())
            }
        }
    }
    .await;
    pool.close().await;
    result
}

/// The second confirmation of protocol 9.1: `--confirm` with the full endpoint ID, or the
/// short ID typed at the terminal.
fn confirmed(key: &EndpointId, confirm: Option<&str>) -> anyhow::Result<()> {
    if let Some(confirm) = confirm {
        if EndpointId::parse(&confirm.to_ascii_lowercase()) == Some(*key) {
            return Ok(());
        }
        bail!("--confirm does not repeat the endpoint ID; nothing was revoked");
    }
    if !io::stdin().is_terminal() {
        bail!(
            "standard input is not a terminal; pass --confirm <ENDPOINT_ID> with the endpoint ID \
             again to revoke without being asked"
        );
    }
    print!("Type the short ID {} to revoke it: ", key.short());
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim().eq_ignore_ascii_case(&key.short()) {
        Ok(())
    } else {
        bail!("the short ID does not match; nothing was revoked")
    }
}
