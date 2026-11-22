//! Rebuilds the crate whenever a migration changes. `sqlx::migrate!` embeds the files of
//! `migrations/sqlite/` and `migrations/mysql/` at compile time, and Cargo does not track them
//! on its own; a directory given to `rerun-if-changed` is watched with everything below it.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
