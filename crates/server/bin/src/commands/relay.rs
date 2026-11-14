//! `gono-cloud relay`: the relay alone, for a host that does not run `serve`.

use std::path::Path;

use anyhow::bail;
use gono_server_relay::Relay;

use super::load_config;
use crate::{
    logging::{self, Destination},
    shutdown,
};

/// Runs the relay of `[relay]` until SIGTERM or Ctrl-C.
pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    if !config.relay.enabled {
        bail!(
            "relay.enabled is false in {}; set it to true to run the relay",
            config_path.display()
        );
    }
    let destination = config
        .logging
        .file
        .clone()
        .map_or(Destination::Stdout, Destination::File);
    let _log_guard = logging::init(config.logging.level, destination)?;
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }
    if config.relay.allowed_endpoints.is_empty() {
        // On a host of its own the relay cannot read the device directory.
        tracing::warn!(
            "relay.allowed_endpoints is empty: a relay on a host of its own admits only the \
             devices listed there, so no device can use it"
        );
    }

    let result = match Relay::spawn(&config.relay, None).await {
        Ok(relay) => relay.run_until(shutdown::wait_for_signal()).await,
        Err(err) => Err(err),
    };
    if let Err(err) = &result {
        // Also record fatal errors in the log, which may be a file.
        tracing::error!("{err:#}");
    }
    result
}
