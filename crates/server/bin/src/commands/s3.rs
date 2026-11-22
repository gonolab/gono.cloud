//! `gono-cloud s3 ...`: S3 access keys and buckets.
//!
//! The secret of a new access key is printed exactly once, to stdout, and never logged. Bucket
//! folders are created and found through the same [`ScopedFs`] the server uses, so a running
//! server and its clients see them like any other change. Changes are written to the audit log
//! of the account as the account page writes them, with the actor `cli`.

use std::{path::Path, sync::Arc};

use anyhow::{Context, bail};
use gono_server_core::{
    Config, RelPath,
    audit::{Actor, Record},
    db,
    meta::MetaStore,
    s3::{self, Anonymous, BucketName, Grant},
    settings,
    storage::DataLayout,
    two_factor, users,
};
use gono_server_dav::{Identity, Mount, ScopedFs};
use secrecy::ExposeSecret as _;

use super::{
    open_database,
    output::{format_optional_time, format_time, print_table},
};
use crate::{
    cli::{S3BucketCommand, S3Command, S3KeyCommand},
    s3::{audit, key_details},
};

/// An audit record of an S3 change made with the command line to account `user_id`.
fn record(user_id: i64, kind: &'static str, details: serde_json::Value) -> Record {
    Record::new(user_id, kind, Actor::Cli).details(details)
}

/// Runs one `s3` subcommand.
pub async fn run(config_path: &Path, command: S3Command) -> anyhow::Result<()> {
    let (config, pool) = open_database(config_path).await?;
    let result = match command {
        S3Command::Key(command) => key(&config, &pool, command).await,
        S3Command::Bucket(command) => bucket(&config, &pool, command).await,
    };
    pool.close().await;
    result
}

async fn key(config: &Config, pool: &db::Pool, command: S3KeyCommand) -> anyhow::Result<()> {
    match command {
        S3KeyCommand::Create {
            username,
            label,
            buckets,
            expires_in_days,
        } => {
            let user = users::get(pool, &username).await?;
            let mut grants = Vec::new();
            for grant in &buckets {
                let bucket = s3::bucket(pool, &grant.name)
                    .await?
                    .filter(|bucket| bucket.owner_id == user.id)
                    .with_context(|| format!("user {username} has no bucket {}", grant.name))?;
                grants.push(Grant {
                    bucket_id: Some(bucket.id),
                    permission: grant.permission,
                });
            }
            if grants.is_empty() {
                grants.push(Grant::everything());
            }
            let sealing = sealing_key(config)?;
            let expires_at =
                expires_in_days.map(|days| db::unix_now() + i64::from(days.get()) * 86_400);
            let (key, secret) =
                s3::create_key(pool, &sealing, user.id, &label, grants, expires_at).await?;
            let buckets = s3::buckets_of(pool, user.id).await?;
            audit(
                pool,
                record(user.id, "s3.key.created", key_details(&key, &buckets)),
            )
            .await;

            println!("Created S3 access key {} for {username}.", key.id);
            println!("  label    {}", key.label);
            println!("  access   {}", describe_grants(pool, &key.grants).await?);
            println!(
                "  expires  {}",
                format_optional_time(key.expires_at, "never")
            );
            println!();
            println!("Access key id: {}", key.access_key_id);
            println!("Secret key:    {}", secret.expose_secret());
            println!();
            match &config.s3.public_url {
                Some(url) => println!(
                    "Endpoint {url}, region {}, path-style addressing.",
                    config.s3.region
                ),
                None => println!(
                    "Set s3.public_url and s3.enabled to serve the S3 API (region {}).",
                    config.s3.region
                ),
            }
            println!("The secret key is shown only once.");
            if !config.s3.enabled {
                println!("Note: the S3 API is off (s3.enabled = false).");
            }
            Ok(())
        }
        S3KeyCommand::List { username } => {
            let user = users::get(pool, &username).await?;
            let mut rows = Vec::new();
            for key in s3::list_keys(pool, user.id).await? {
                rows.push(vec![
                    key.id.to_string(),
                    key.access_key_id.clone(),
                    key.label.clone(),
                    format_time(key.created_at),
                    format_optional_time(key.expires_at, "never"),
                    format_optional_time(key.last_used_at, "never"),
                    describe_grants(pool, &key.grants).await?,
                ]);
            }
            print_table(
                &[
                    "ID",
                    "ACCESS KEY ID",
                    "LABEL",
                    "CREATED",
                    "EXPIRES",
                    "LAST USED",
                    "ACCESS",
                ],
                &rows,
            );
            Ok(())
        }
        S3KeyCommand::Delete { username, id } => {
            let user = users::get(pool, &username).await?;
            let key = s3::list_keys(pool, user.id)
                .await?
                .into_iter()
                .find(|key| key.id == id);
            if key.is_none() || !s3::delete_key(pool, user.id, id).await? {
                bail!("user {username} has no S3 access key with id {id}");
            }
            if let Some(key) = key {
                let details = serde_json::json!({
                    "access_key_id": key.access_key_id,
                    "label": key.label,
                });
                audit(pool, record(user.id, "s3.key.revoked", details)).await;
            }
            println!("Revoked S3 access key {id} of {username}.");
            Ok(())
        }
    }
}

/// `all buckets:full` or `photos:view, media:full`.
async fn describe_grants(pool: &db::Pool, grants: &[Grant]) -> anyhow::Result<String> {
    let mut parts = Vec::with_capacity(grants.len());
    for grant in grants {
        let name = match grant.bucket_id {
            None => "all buckets".to_owned(),
            Some(id) => s3::bucket_by_id(pool, id)
                .await?
                .map_or_else(|| format!("#{id}"), |bucket| bucket.name),
        };
        parts.push(format!("{name}:{}", grant.permission));
    }
    Ok(parts.join(", "))
}

/// The key that S3 secrets are sealed with: the file of `two_factor.key_file`, created if it
/// does not exist yet (as `init` and `serve` do).
fn sealing_key(config: &Config) -> anyhow::Result<two_factor::Key> {
    let path = &config.two_factor.key_file;
    if let Some(key) = two_factor::Key::load(path)
        .with_context(|| format!("read two_factor.key_file {}", path.display()))?
    {
        return Ok(key);
    }
    two_factor::Key::create(path)
        .with_context(|| format!("create two_factor.key_file {}", path.display()))?;
    two_factor::Key::load(path)?
        .with_context(|| format!("two_factor.key_file {} cannot be read", path.display()))
}

/// The tree of `config` as the server sees it.
async fn tree(config: &Config, pool: &db::Pool) -> anyhow::Result<ScopedFs> {
    let layout = DataLayout::new(&config.storage.data_dir);
    layout.open().context("open data directory")?;
    let instance_id = settings::instance_id(pool).await?;
    Ok(ScopedFs::new(
        layout,
        MetaStore::new(pool.clone()),
        instance_id,
    ))
}

/// The whole tree of `user`, writable.
fn owner_identity(user: &users::User) -> Arc<Identity> {
    Arc::new(Identity {
        user_id: user.id,
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        app_password_id: None,
        // The CLI acts for the owner on the server's host; no service applies.
        services: user.services,
        mounts: vec![Mount {
            mount_path: RelPath::root(),
            storage_path: RelPath::root(),
            writable: true,
        }],
    })
}

async fn bucket(config: &Config, pool: &db::Pool, command: S3BucketCommand) -> anyhow::Result<()> {
    match command {
        S3BucketCommand::List { username } => {
            let user = users::get(pool, &username).await?;
            let rows: Vec<Vec<String>> = s3::buckets_of(pool, user.id)
                .await?
                .into_iter()
                .map(|bucket| {
                    vec![
                        bucket.name,
                        bucket.folder.to_string(),
                        bucket.anonymous.as_str().to_owned(),
                        if bucket.anonymous_list { "yes" } else { "no" }.to_owned(),
                        format_time(bucket.created_at),
                    ]
                })
                .collect();
            print_table(
                &["NAME", "FOLDER", "ANONYMOUS", "ANONYMOUS LIST", "CREATED"],
                &rows,
            );
            Ok(())
        }
        S3BucketCommand::Create { username, name } => {
            let user = users::get(pool, &username).await?;
            let name = BucketName::new(&name)?;
            let folder = RelPath::root()
                .join(&config.s3.bucket_folder)
                .join(name.as_str());
            let fs = tree(config, pool).await?;
            let identity = owner_identity(&user);
            if fs.stat(identity.clone(), &folder).await.is_ok() {
                bail!(
                    "{folder} exists already; bind it with `gono-cloud s3 bucket bind {username} \
                     {name} {folder}`"
                );
            }
            let entry = fs
                .put_folder(identity, &folder)
                .await
                .with_context(|| format!("create the folder {folder}"))?;
            let folder_id = entry.file_id.context("the new folder has no file id")?;
            let bucket = s3::create_bucket(pool, user.id, &name, folder_id).await?;
            let details = serde_json::json!({ "bucket": bucket.name, "new_folder": true });
            audit(pool, record(user.id, "s3.bucket.created", details)).await;
            println!(
                "Created bucket {} of {username} in the folder {}.",
                bucket.name, bucket.folder
            );
            Ok(())
        }
        S3BucketCommand::Bind {
            username,
            name,
            folder,
        } => {
            let user = users::get(pool, &username).await?;
            let name = BucketName::new(&name)?;
            let path =
                RelPath::parse(&folder).map_err(|source| gono_server_core::Error::InvalidPath {
                    path: folder.clone(),
                    source,
                })?;
            let fs = tree(config, pool).await?;
            let entry = fs
                .stat(owner_identity(&user), &path)
                .await
                .map_err(|_| anyhow::anyhow!("user {username} has no folder {folder}"))?;
            if !entry.is_dir() {
                bail!("{folder} is a file, not a folder");
            }
            let folder_id = entry.file_id.context("the folder has no file id")?;
            let bucket = s3::create_bucket(pool, user.id, &name, folder_id).await?;
            let details = serde_json::json!({ "bucket": bucket.name, "new_folder": false });
            audit(pool, record(user.id, "s3.bucket.created", details)).await;
            println!(
                "Bound {} as bucket {} of {username}.",
                bucket.folder, bucket.name
            );
            Ok(())
        }
        S3BucketCommand::Set {
            username,
            name,
            anonymous,
            list,
            no_list,
        } => {
            let user = users::get(pool, &username).await?;
            let bucket = s3::bucket(pool, &name)
                .await?
                .filter(|bucket| bucket.owner_id == user.id)
                .with_context(|| format!("user {username} has no bucket {name}"))?;
            let list = list && !no_list && anonymous.0 != Anonymous::Private;
            s3::set_anonymous(pool, user.id, bucket.id, anonymous.0, list).await?;
            let details = serde_json::json!({
                "bucket": bucket.name,
                "anonymous": anonymous.0.as_str(),
                "list": list,
            });
            audit(pool, record(user.id, "s3.bucket.anonymous", details)).await;
            println!(
                "Bucket {name}: anonymous reads {}, anonymous listing {}.",
                anonymous.0.as_str(),
                if list { "on" } else { "off" }
            );
            if anonymous.0 != Anonymous::Private && !config.s3.allow_anonymous {
                println!(
                    "Note: anonymous access is off on this server (s3.allow_anonymous = false); \
                     the bucket answers as private until it is turned on."
                );
            }
            Ok(())
        }
        S3BucketCommand::Unbind { username, name } => {
            let user = users::get(pool, &username).await?;
            let bucket = s3::bucket(pool, &name)
                .await?
                .filter(|bucket| bucket.owner_id == user.id)
                .with_context(|| format!("user {username} has no bucket {name}"))?;
            s3::delete_bucket(pool, user.id, bucket.id).await?;
            let details = serde_json::json!({ "bucket": bucket.name });
            audit(pool, record(user.id, "s3.bucket.removed", details)).await;
            println!(
                "Removed bucket {name}; the folder {} and its files stay.",
                bucket.folder
            );
            Ok(())
        }
    }
}
