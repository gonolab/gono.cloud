//! `gono-cloud config check`.

use std::path::{Path, PathBuf};

use gono_server_core::{
    config::{DbConfig, RelayConfig, S3Config},
    db::Backend,
};

use super::load_config;

/// Validates the config file and prints the effective settings, with relative paths resolved.
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;

    let proxies = if config.server.trusted_proxies.is_empty() {
        "(none)".to_owned()
    } else {
        config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let log_file = config
        .logging
        .file
        .as_ref()
        .map_or_else(|| "(stdout)".to_owned(), |file| file.display().to_string());

    println!("Configuration OK: {}", config_path.display());
    println!();
    let mut settings = vec![
        ("server.bind", config.server.bind.to_string()),
        ("server.base_url", config.server.base_url.to_string()),
        ("server.trusted_proxies", proxies),
        (
            "storage.data_dir",
            config.storage.data_dir.display().to_string(),
        ),
    ];
    settings.extend(db_settings(&config.db));
    settings.extend([
        (
            "two_factor.key_file",
            format!(
                "{}{}",
                config.two_factor.key_file.display(),
                if config.two_factor.key_file.exists() {
                    ""
                } else {
                    " (missing)"
                }
            ),
        ),
        (
            "webdav.max_lock_timeout_secs",
            config.webdav.max_lock_timeout_secs.to_string(),
        ),
        ("logging.level", config.logging.level.as_str().to_owned()),
        ("logging.file", log_file),
        (
            "notify_push.enabled",
            config.notify_push.enabled.to_string(),
        ),
        ("admin.enabled", config.admin.enabled.to_string()),
        ("files_ui.enabled", config.files_ui.enabled.to_string()),
        ("admin.path", config.admin.path.clone()),
        ("relay.enabled", config.relay.enabled.to_string()),
    ]);
    if config.relay.enabled {
        settings.extend(relay_settings(&config.relay));
        settings.push((
            "connect.require_two_factor",
            config.connect.require_two_factor.to_string(),
        ));
    }
    settings.push(("s3.enabled", config.s3.enabled.to_string()));
    if config.s3.enabled {
        settings.extend(s3_settings(&config.s3));
    }
    for (key, value) in settings {
        println!("  {key:<31} {value}");
    }

    let warnings = config.warnings();
    if !warnings.is_empty() {
        println!();
        for warning in warnings {
            println!("warning: {warning}");
        }
    }
    Ok(())
}

/// The effective settings of the database. The MySQL URL carries no password (validation
/// refuses one), and the password file is named, never read here.
fn db_settings(db: &DbConfig) -> Vec<(&'static str, String)> {
    let mut settings = vec![("db.backend", db.backend.as_str().to_owned())];
    match db.backend {
        Backend::Sqlite => settings.push(("db.path", db.path.display().to_string())),
        Backend::MySql => {
            settings.push((
                "db.url",
                db.url
                    .as_ref()
                    .map_or_else(|| "(none)".to_owned(), ToString::to_string),
            ));
            settings.push((
                "db.password_file",
                db.password_file.as_ref().map_or_else(
                    || "(none: the account has no password)".to_owned(),
                    |file| {
                        format!(
                            "{}{}",
                            file.display(),
                            if file.exists() { "" } else { " (missing)" }
                        )
                    },
                ),
            ));
        }
    }
    settings.extend([
        ("db.max_connections", db.max_connections.to_string()),
        ("db.busy_timeout_secs", db.busy_timeout_secs.to_string()),
    ]);
    settings
}

/// The effective settings of an enabled S3 API.
fn s3_settings(s3: &S3Config) -> Vec<(&'static str, String)> {
    vec![
        (
            "s3.public_url",
            s3.public_url
                .as_ref()
                .map_or_else(|| "(none)".to_owned(), ToString::to_string),
        ),
        ("s3.bind", s3.bind.to_string()),
        ("s3.region", s3.region.clone()),
        ("s3.bucket_folder", s3.bucket_folder.clone()),
        ("s3.allow_anonymous", s3.allow_anonymous.to_string()),
        ("s3.multipart_ttl_secs", s3.multipart_ttl_secs.to_string()),
        (
            "s3.virtual_host_domain",
            s3.virtual_host_domain
                .clone()
                .unwrap_or_else(|| "(none: path style only)".to_owned()),
        ),
    ]
}

/// The effective settings of an enabled relay.
fn relay_settings(relay: &RelayConfig) -> Vec<(&'static str, String)> {
    let optional = |value: Option<String>| value.unwrap_or_else(|| "(none)".to_owned());
    let path = |path: Option<&PathBuf>| optional(path.map(|path| path.display().to_string()));
    vec![
        (
            "relay.public_url",
            optional(relay.public_url.as_ref().map(ToString::to_string)),
        ),
        ("relay.bind", relay.bind.to_string()),
        (
            "relay.qad_bind",
            relay.qad_bind.map_or_else(
                || "(off: no QUIC address discovery)".to_owned(),
                |bind| bind.to_string(),
            ),
        ),
        ("relay.tls_cert", path(relay.tls_cert.as_ref())),
        ("relay.tls_key", path(relay.tls_key.as_ref())),
        (
            "relay.tls_reload_interval_secs",
            relay.tls_reload_interval_secs.to_string(),
        ),
        (
            "relay.allowed_endpoints",
            format!("{} device ids", relay.allowed_endpoints.len()),
        ),
        (
            "relay.max_client_bytes_per_sec",
            match (relay.max_client_bytes_per_sec, relay.max_client_burst_bytes) {
                (None, _) => "(unlimited)".to_owned(),
                (Some(rate), None) => rate.to_string(),
                (Some(rate), Some(burst)) => format!("{rate} (bursts of {burst} bytes)"),
            },
        ),
    ]
}
