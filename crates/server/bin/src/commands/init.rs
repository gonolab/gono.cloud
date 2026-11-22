//! `gono-cloud init`.

use std::path::Path;

use anyhow::Context;
use gono_server_core::{
    Error, PRODUCT_NAME,
    config::LogLevel,
    db::{self, OpenMode},
    password,
    storage::DataLayout,
    two_factor, users,
};

use super::{load_config, refuse_root_on_foreign_install};
use crate::{
    cli::InitArgs,
    logging::{self, Destination},
    password_input,
};

/// Creates the data directory layout and the database, applies the migrations and creates the
/// first admin account with its storage directories.
///
/// Refuses to run against a database that already has accounts. The admin's web login password
/// is read from the terminal or stdin and is never printed or logged.
pub async fn run(config_path: &Path, args: InitArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    refuse_root_on_foreign_install(&config)?;
    let _log_guard = logging::init(LogLevel::Warn, Destination::Stderr)?;
    let display_name = users::display_name_or_default(args.display_name.as_deref(), &args.admin)?;

    let layout = DataLayout::new(&config.storage.data_dir);
    layout.create().context("create data directory")?;
    let pool = db::connect(&config.db, OpenMode::CreateIfMissing)
        .await
        .context("create database")?;
    db::migrate(&pool)
        .await
        .context("apply database migrations")?;

    // Checked again inside the insert transaction; this early check only avoids prompting for a
    // password that would be thrown away.
    if users::count(&pool).await? > 0 {
        pool.close().await;
        return Err(Error::AlreadyInitialized.into());
    }

    let username = args.admin.clone();
    let source = args.password;
    let password =
        tokio::task::spawn_blocking(move || password_input::read_new_password(source, &username))
            .await??;
    let password_hash = tokio::task::spawn_blocking(move || password::hash(&password)).await??;

    let user_id =
        users::create_initial_admin(&pool, &args.admin, &display_name, &password_hash).await?;
    pool.close().await;
    layout
        .create_user(user_id)
        .context("create the admin's storage directories")?;

    // The key of two-step verification. The install script creates it as root, since the
    // service user cannot write the configuration directory; a manual setup gets it here.
    let key_file = &config.two_factor.key_file;
    let key = match two_factor::Key::create(key_file) {
        Ok(true) => format!("{} (created)", key_file.display()),
        Ok(false) => key_file.display().to_string(),
        Err(err) => {
            eprintln!(
                "warning: cannot create the two-step verification key {}: {err:#}; create it with \
                 32 random bytes, readable by the service, before turning two-step verification on",
                key_file.display()
            );
            format!("{} (missing)", key_file.display())
        }
    };

    println!("Initialized {PRODUCT_NAME}.");
    println!();
    println!("  database        {}", config.db.describe());
    println!("  data directory  {}", config.storage.data_dir.display());
    println!("  two-step key    {key}");
    println!("  admin account   {}", args.admin);
    println!();
    println!(
        "Accounts start without services, this one too. Turn them on in the admin UI or with \
         `gono-cloud user services {} --enable all`.",
        args.admin
    );
    println!("Start the server with `gono-cloud serve`.");
    Ok(())
}
