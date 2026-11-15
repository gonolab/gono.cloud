//! `gono-cloud serve`.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::Context;
use dav_server::{DavHandler, DavMethodSet};
use gono_server_connect::{Connect, ConnectConfig};
use gono_server_core::{
    Config, audit,
    db::{self, OpenMode},
    locks::LockStore,
    meta::MetaStore,
    settings,
    storage::DataLayout,
    two_factor, users,
};
use gono_server_dav::{DavService, ScopedFs, locks::SqliteLs};
use gono_server_nextcloud::{
    chunking::ChunkedUploads,
    notify_push::{self, Hub, PushSettings},
};
use gono_server_relay::{Admission, Relay};
use tokio::{net::TcpListener, sync::Notify};

use super::{load_config, refuse_root_on_foreign_install};
use crate::{
    admin::{Admin, ServerInfo},
    app::{self, AppState},
    auth::Authenticator,
    files::Files,
    janitor::Janitor,
    logging::{self, Destination},
    ratelimit::RateLimiter,
    shutdown,
    web::Web,
};

/// How long the relay may take to stop once the HTTP server has.
const RELAY_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs the HTTP server until SIGTERM or Ctrl-C.
pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    refuse_root_on_foreign_install(&config)?;
    let destination = config
        .logging
        .file
        .clone()
        .map_or(Destination::Stdout, Destination::File);
    let _log_guard = logging::init(config.logging.level, destination)?;

    let config_path = std::path::absolute(config_path).unwrap_or_else(|_| config_path.into());
    let result = serve(config, config_path).await;
    if let Err(err) = &result {
        // Also record fatal errors in the log, which may be a file.
        tracing::error!("{err:#}");
    }
    result
}

async fn serve(config: Config, config_path: std::path::PathBuf) -> anyhow::Result<()> {
    let started_at = db::unix_now();
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let pool = db::connect(&config.db, OpenMode::MustExist)
        .await
        .context("open database")?;
    db::migrate(&pool)
        .await
        .context("apply database migrations")?;
    if users::count(&pool).await? == 0 {
        tracing::warn!("no user accounts exist; run `gono-cloud init`");
    }
    let layout = DataLayout::new(&config.storage.data_dir);
    layout.open().context("open data directory")?;
    let case_insensitive = match layout.is_case_insensitive() {
        Ok(true) => {
            tracing::warn!(
                data_dir = %layout.root().display(),
                "the data directory is on a case-insensitive file system: names that differ \
                 only in case (Report.pdf, report.pdf) cannot coexist, although clients on \
                 other systems may create them; a case-sensitive file system is recommended"
            );
            Some(true)
        }
        Ok(false) => Some(false),
        Err(err) => {
            tracing::warn!(error = %err, "cannot tell whether the data directory ignores case");
            None
        }
    };
    let purged = LockStore::new(pool.clone())
        .purge_expired(db::unix_now())
        .await?;
    if purged > 0 {
        tracing::debug!(purged, "removed expired WebDAV locks");
    }

    let bind = config.server.bind;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("listen on {bind}"))?;
    let local_addr = listener.local_addr().context("read listener address")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        address = %local_addr,
        base_url = %config.server.base_url,
        "listening"
    );

    // Remote connectivity: the device directory and the control channel, with the relay. It
    // needs an HTTPS origin, since devices send their credentials to it.
    let connect = if config.relay.enabled {
        let base_url = &config.server.base_url;
        if ConnectConfig::allowed_origin(base_url) {
            let relay_url = config
                .relay
                .public_url
                .clone()
                .context("relay.public_url is not set")?;
            let connect = Connect::new(
                pool.clone(),
                ConnectConfig {
                    base_url: base_url.clone(),
                    relay_url,
                    audit_retention_secs: audit::DEFAULT_RETENTION_SECS,
                },
            )
            .await
            .context("read the device directory")?;
            tracing::info!("remote connectivity enabled at /gono/v1/");
            Some(connect)
        } else {
            tracing::warn!(
                "remote connectivity is off: it needs an https server.base_url; the relay admits \
                 only relay.allowed_endpoints"
            );
            None
        }
    } else {
        None
    };

    // The relay serves devices beside the HTTP server. A relay that cannot start stops the
    // start, like any other configuration error; one that fails later is logged and leaves the
    // file server running.
    let relay_stop = Arc::new(Notify::new());
    let (relay_status, relay_task) = if config.relay.enabled {
        let admission = connect
            .as_ref()
            .map(|connect| connect.directory() as Arc<dyn Admission>);
        let relay = Relay::spawn(&config.relay, admission)
            .await
            .context("start the relay")?;
        let status = relay.status();
        if let Some(connect) = &connect {
            connect.set_relay(status.clone());
        }
        let stop = Arc::clone(&relay_stop);
        let task = tokio::spawn(async move {
            if let Err(err) = relay.run_until(stop.notified()).await {
                tracing::error!("{err:#}");
            }
        });
        (Some(status), Some(task))
    } else {
        (None, None)
    };

    // notify_push announces changes committed from now on; older ones are history.
    let push = if config.notify_push.enabled {
        let watermark = MetaStore::new(pool.clone())
            .latest_change_id()
            .await
            .context("read the change log")?;
        Some(Hub::new(
            PushSettings::from_config(&config.notify_push),
            watermark,
        ))
    } else {
        None
    };
    let mut meta = MetaStore::new(pool.clone());
    if let Some(hub) = &push {
        meta = meta.with_sink(hub.clone());
    }
    let feed = push
        .clone()
        .map(|hub| tokio::spawn(notify_push::run_feed(hub, meta.clone())));

    let dav = dav_service(
        Duration::from_secs(config.webdav.max_lock_timeout_secs),
        layout,
        meta,
    )
    .await?;
    let uploads = ChunkedUploads::new(dav.fs().clone(), LockStore::new(pool.clone()));
    let janitor = Janitor {
        db: pool.clone(),
        uploads: uploads.clone(),
    }
    .spawn();
    let auth = Arc::new(Authenticator::new(
        pool.clone(),
        Arc::new(RateLimiter::new()),
    ));
    // The HTML sign-in has a limiter of its own: failing devices must not block it, and its
    // policy differs (see `crate::ratelimit`).
    let mut web = Web::new(
        pool.clone(),
        Arc::new(RateLimiter::new()),
        &config.server.base_url,
    );
    if let Some(key) = two_factor_key(&config, &pool).await? {
        web = web.with_two_factor_key(key);
    }
    let web = Arc::new(web);
    let admin = if config.admin.enabled {
        let info = ServerInfo {
            started_at,
            instance_id: dav.fs().instance_id().to_owned(),
            bind: local_addr,
            trusted_proxies: config.server.trusted_proxies.clone(),
            config_path,
            log: format!(
                "{} → {}",
                config.logging.level.as_str(),
                config
                    .logging
                    .file
                    .as_ref()
                    .map_or_else(|| "stdout".to_owned(), |file| file.display().to_string())
            ),
            data_dir: config.storage.data_dir.clone(),
            db_path: config.db.path.clone(),
            case_insensitive,
            lock_timeout_secs: config.webdav.max_lock_timeout_secs,
            push: push.as_ref().map(|hub| *hub.settings()),
            relay: relay_status,
            warnings: config.warnings(),
        };
        tracing::info!(path = %config.admin.path, "web admin UI enabled");
        Some(Arc::new(Admin::new(&config.admin.path, info)))
    } else {
        None
    };
    let files = if config.files_ui.enabled {
        tracing::info!("web file UI enabled at /apps/files/");
        Some(Arc::new(Files::new()))
    } else {
        None
    };
    let state = AppState {
        db: pool.clone(),
        auth,
        dav,
        uploads,
        web,
        base_url: Arc::new(config.server.base_url.clone()),
        flow_starts: Arc::new(RateLimiter::new()),
        trusted_proxies: Arc::new(config.server.trusted_proxies.clone()),
        push: push.clone(),
        admin,
        files,
        connect: connect.clone(),
    };
    let connect_task = connect.clone().map(|connect| tokio::spawn(connect.run()));
    let on_signal = {
        let push = push.clone();
        let connect = connect.clone();
        let relay_stop = Arc::clone(&relay_stop);
        move || {
            if let Some(hub) = push {
                hub.shut_down();
            }
            if let Some(connect) = connect {
                connect.shut_down();
            }
            // Relay connections are not HTTP requests of this server: end them at once.
            relay_stop.notify_one();
        }
    };
    let result = shutdown::serve(listener, app::router(state), on_signal).await;
    if let Some(hub) = &push {
        hub.shut_down();
    }
    if let Some(task) = relay_task {
        relay_stop.notify_one();
        if tokio::time::timeout(RELAY_STOP_TIMEOUT, task)
            .await
            .is_err()
        {
            tracing::warn!("the relay did not stop in time");
        }
    }
    if let Some(feed) = feed {
        feed.abort();
    }
    if let Some(connect) = &connect {
        connect.shut_down();
    }
    if let Some(task) = connect_task {
        task.abort();
    }
    janitor.abort();
    pool.close().await;
    tracing::info!("stopped");
    result
}

/// The key of two-step verification (`two_factor.key_file`). A missing file is created when
/// no account has two-step verification yet; without it, enrolled accounts could not sign in,
/// so its absence stops the start then. When it cannot be created, two-step verification is
/// unavailable and the start goes on.
async fn two_factor_key(
    config: &Config,
    pool: &db::Pool,
) -> anyhow::Result<Option<two_factor::Key>> {
    let path = &config.two_factor.key_file;
    let read = |path: &Path| {
        two_factor::Key::load(path)
            .with_context(|| format!("read two_factor.key_file {}", path.display()))
    };
    if let Some(key) = read(path)? {
        warn_if_readable_by_others(path);
        return Ok(Some(key));
    }
    if two_factor::any_enrolled(pool).await? {
        anyhow::bail!(
            "two_factor.key_file {} is missing, but accounts have two-step verification on: \
             restore the file from a backup, or reset their two-step verification with \
             `gono-cloud user reset-two-factor`",
            path.display()
        );
    }
    match two_factor::Key::create(path) {
        Ok(created) => {
            if created {
                tracing::info!(path = %path.display(), "created the two-step verification key");
            }
            // Another process may have created it meanwhile: then its key is the one to use.
            let key = read(path)?;
            if key.is_none() {
                tracing::warn!(
                    path = %path.display(),
                    "two-step verification is unavailable: two_factor.key_file is a symbolic \
                     link to a missing file; restore its target or remove the link"
                );
            }
            Ok(key)
        }
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "two-step verification is unavailable: two_factor.key_file does not exist and \
                 cannot be created; create it with 32 random bytes, readable by the service \
                 (docs/deployment.md)"
            );
            Ok(None)
        }
    }
}

/// Warns when the key file is readable by everyone.
fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(metadata) = std::fs::metadata(path)
            && metadata.permissions().mode() & 0o004 != 0
        {
            tracing::warn!(
                path = %path.display(),
                "two_factor.key_file is readable by every user of this host; make it 0640"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Builds the one `DavHandler` of the process and the service around it. Every metadata
/// change goes through `meta`, which publishes it to its sink.
pub(crate) async fn dav_service(
    max_lock_timeout: Duration,
    layout: DataLayout,
    meta: MetaStore,
) -> anyhow::Result<DavService> {
    let pool = meta.pool().clone();
    let instance_id = settings::instance_id(&pool)
        .await
        .context("read the instance id")?;
    let fs = ScopedFs::new(layout, meta, instance_id);
    let locks = SqliteLs::new(LockStore::new(pool), max_lock_timeout);
    // REPORT (filter-files) is served outside dav-server; CalDAV and CardDAV are not offered.
    let mut methods = DavMethodSet::all();
    for method in [
        dav_server::DavMethod::Report,
        dav_server::DavMethod::MkCalendar,
        dav_server::DavMethod::MkAddressbook,
    ] {
        methods.remove(method);
    }
    let handler = DavHandler::builder()
        .filesystem(Box::new(fs.clone()))
        .locksystem(locks)
        .methods(methods)
        .build_handler();
    Ok(DavService::new(handler, fs))
}
