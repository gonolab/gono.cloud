//! `gono-cloud rescan`: bring the metadata in line with files changed behind the server's back.
//!
//! For every selected account, [`rescan::walk`] lists the tree (renaming names that are not
//! NFC) and [`MetaStore::reconcile`] updates the metadata in one transaction, logging every
//! change so that a running server announces it over notify_push within seconds. A dry run
//! does both steps without changing anything and prints the same report.
//!
//! With `--checksums`, the MD5 of every file in the scope that has none is computed afterwards
//! ([`fill_checksums`]) and recorded for the version that was read, if it is still the current
//! one; a dry run only counts them.

use std::{fmt::Display, io::Read as _, path::Path};

use anyhow::{Context, bail};
use gono_server_core::{
    RelPath,
    meta::{DiskStat, FileRow, MetaStore, Reconciled},
    rescan::{self, Walk},
    storage::{DataLayout, lstat_beneath},
    users::{self, User},
};
use md5::{Digest as _, Md5};

use super::open_database;
use crate::cli::RescanArgs;

/// Lines printed per kind of change before the rest is summarized.
const MAX_LINES: usize = 20;

/// Runs `gono-cloud rescan`.
pub async fn run(config_path: &Path, args: RescanArgs) -> anyhow::Result<()> {
    let (config, pool) = open_database(config_path).await?;
    let result = rescan_all(&config.storage.data_dir, &pool, args).await;
    pool.close().await;
    result
}

async fn rescan_all(
    data_dir: &Path,
    pool: &gono_server_core::db::Pool,
    args: RescanArgs,
) -> anyhow::Result<()> {
    let layout = DataLayout::new(data_dir);
    let meta = MetaStore::new(pool.clone());
    let scope = match &args.path {
        Some(path) => RelPath::parse(path).with_context(|| format!("invalid path {path:?}"))?,
        None => RelPath::root(),
    };
    let accounts: Vec<User> = match &args.username {
        Some(username) => vec![users::get(pool, username).await?],
        None => users::list(pool).await?,
    };
    if args.dry_run {
        println!("Dry run: nothing is changed; the report shows what would change.");
    }
    let mut totals = Reconciled::default();
    let mut problems = 0;
    for user in &accounts {
        let root = layout.user_files(user.id);
        if args.all && !root.is_dir() {
            println!("\n{}: no files yet, skipped.", user.username);
            continue;
        }
        let walked = {
            let (root, scope, dry_run) = (root.clone(), scope.clone(), args.dry_run);
            tokio::task::spawn_blocking(move || rescan::walk(&root, &scope, dry_run))
                .await?
                .with_context(|| format!("scan the files of {}", user.username))?
        };
        if !walked.scope_exists && meta.get(user.id, &scope).await?.is_none() {
            bail!("{scope} does not exist in the files of {}", user.username);
        }
        let report = meta
            .reconcile(
                user.id,
                &scope,
                &walked.ancestors,
                &walked.entries,
                args.dry_run,
            )
            .await
            .with_context(|| format!("update the metadata of {}", user.username))?;
        print_report(user, &scope, &walked, &report, args.dry_run);
        if args.checksums {
            let filled = fill_checksums(&meta, &root, user, &scope, args.dry_run).await?;
            print_checksums(&filled, args.dry_run);
        }
        problems += walked.conflicts.len() + walked.skipped.len();
        totals.added_rows += report.added_rows;
        totals.removed_rows += report.removed_rows;
        totals.modified.extend(report.modified);
        totals.resized += report.resized;
    }
    if accounts.len() > 1 {
        println!(
            "\nAll accounts: added: {}, removed: {}, modified: {}, folder sizes corrected: {}, \
             entries that need attention (conflicts, skipped): {}.",
            totals.added_rows,
            totals.removed_rows,
            totals.modified.len(),
            totals.resized,
            problems
        );
    }
    Ok(())
}

/// Files without an MD5 read per database query.
const CHECKSUM_BATCH: u32 = 500;

/// What [`fill_checksums`] did.
#[derive(Debug, Default)]
struct Checksums {
    /// Files without an MD5 in the scope.
    missing: usize,
    /// MD5s recorded.
    computed: usize,
    /// Files that changed or went away while they were read, or are not as recorded (a
    /// regular rescan updates them first).
    skipped: usize,
}

/// Computes and records the MD5 of every file of `user` in `scope` (below `root` on disk)
/// that has none. The MD5 is recorded only for the version it was read from (same ETag), and
/// only if the file on disk is the one the metadata describes.
async fn fill_checksums(
    meta: &MetaStore,
    root: &Path,
    user: &User,
    scope: &RelPath,
    dry_run: bool,
) -> anyhow::Result<Checksums> {
    let mut done = Checksums::default();
    let mut after = 0;
    loop {
        let batch = meta
            .files_without_md5(Some(user.id), after, CHECKSUM_BATCH)
            .await?;
        let Some((_, last)) = batch.last() else {
            return Ok(done);
        };
        after = last.id;
        for (_, row) in batch {
            if !scope.is_root() && !row.rel_path.starts_with(scope) {
                continue;
            }
            done.missing += 1;
            if dry_run {
                continue;
            }
            let read = {
                let (root, row) = (root.to_path_buf(), row.clone());
                tokio::task::spawn_blocking(move || md5_of_recorded(&root, &row)).await?
            };
            let recorded = match read {
                Ok(Some(md5)) => meta.set_md5(row.id, &row.etag, md5).await?,
                Ok(None) => false,
                Err(err) => {
                    tracing::warn!(path = %row.rel_path, error = %err, "cannot read a file");
                    false
                }
            };
            if recorded {
                done.computed += 1;
            } else {
                done.skipped += 1;
            }
        }
    }
}

/// The MD5 of the file `row` describes, below `root`: `None` if it is not there as recorded
/// (a symbolic link on the way, another size or modification time).
fn md5_of_recorded(root: &Path, row: &FileRow) -> std::io::Result<Option<[u8; 16]>> {
    let Some(before) = lstat_beneath(root, &row.rel_path)? else {
        return Ok(None);
    };
    let stat = DiskStat::from_metadata(&before);
    if stat.is_dir || stat.size != row.size || stat.mtime_ns != row.mtime_ns {
        return Ok(None);
    }
    let mut file = std::fs::File::open(row.rel_path.to_fs_path(root))?;
    // The file opened must still be the one checked above.
    if DiskStat::from_metadata(&file.metadata()?) != stat {
        return Ok(None);
    }
    let mut hasher = Md5::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(Some(hasher.finalize().into()));
        }
        hasher.update(&buffer[..read]);
    }
}

fn print_checksums(done: &Checksums, dry_run: bool) {
    if dry_run {
        println!("  files without an MD5: {}", done.missing);
    } else if done.missing > 0 {
        println!(
            "  MD5s computed: {}, skipped (changed, or not as recorded): {}",
            done.computed, done.skipped
        );
    }
}

/// Prints up to [`MAX_LINES`] lines of one kind of change.
fn print_lines<T: Display>(label: &str, items: impl ExactSizeIterator<Item = T>) {
    let count = items.len();
    for item in items.take(MAX_LINES) {
        println!("  {label} {item}");
    }
    if count > MAX_LINES {
        println!("  ... and {} more", count - MAX_LINES);
    }
}

fn print_report(user: &User, scope: &RelPath, walk: &Walk, report: &Reconciled, dry_run: bool) {
    let verb = |done: &'static str, would: &'static str| if dry_run { would } else { done };
    println!("\n{} {scope}", user.username);
    if !walk.scope_exists {
        println!(
            "  {scope} is gone from the disk; its metadata {}.",
            verb("was removed", "would be removed")
        );
    }
    print_lines(
        verb("renamed to NFC:  ", "would rename to NFC:"),
        walk.renamed.iter(),
    );
    print_lines(
        "NOT renamed (the NFC name is taken):",
        walk.conflicts.iter().map(|conflict| &conflict.path),
    );
    print_lines(
        "skipped:",
        walk.skipped.iter().map(|skipped| {
            let mut path = skipped.dir.to_string();
            if !path.ends_with('/') {
                path.push('/');
            }
            format!(
                "{path}{} ({})",
                skipped.name.escape_debug(),
                skipped.reason.describe()
            )
        }),
    );
    print_lines(verb("added:   ", "would add:   "), report.added.iter());
    print_lines(verb("removed: ", "would remove:"), report.removed.iter());
    print_lines(verb("modified:", "would modify:"), report.modified.iter());
    println!(
        "  Summary: {} entries on disk ({} folders, {} files). Renamed to NFC: {}, conflicts: \
         {}, skipped: {}. Added: {}, removed: {}, modified: {}, folder sizes corrected: {}.",
        walk.entries.len(),
        walk.dirs(),
        walk.files(),
        walk.renamed.len(),
        walk.conflicts.len(),
        walk.skipped.len(),
        report.added_rows,
        report.removed_rows,
        report.modified.len(),
        report.resized,
    );
    if report.is_empty() && walk.renamed.is_empty() {
        println!("  Everything was up to date.");
    }
}
