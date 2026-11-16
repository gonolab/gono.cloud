//! S3 views of the `files` table: object metadata (`object_meta`) and listings in S3 key order.
//!
//! A bucket is a folder of its owner's tree; its objects are the files below that folder, and
//! an object's key is the file's `rel_path` relative to the folder. The S3 API itself lives in
//! another crate; this module holds what depends on the metadata model.
//!
//! # Listing order
//!
//! S3 lists keys in the byte order of their UTF-8 encoding. `rel_path` uses `BINARY` collation,
//! which is that order, and stripping the folder's prefix keeps it. [`MetaStore::list_objects`]
//! therefore reads file rows in `rel_path` order and never derives common prefixes from
//! directory rows: the folder `a` sorts before the file `a-b`, while S3 orders the common prefix
//! `a/` after the key `a-b` (`-` is 0x2D, `/` is 0x2F). Common prefixes come from the first file
//! below them, and the scan then jumps past all their keys with one indexed seek
//! ([`prefix_successor`]). Directories without files never show up, as in S3.

use std::collections::BTreeMap;

use sqlx::FromRow;

use super::store::{FileRow, MetaStore, Row};
use crate::{db, error::Result, path::RelPath};

/// The S3 metadata of the current version of a file (see the `object_meta` table).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectMeta {
    /// The S3 ETag without quotes; `None` when the version was not written through the S3 API
    /// (its S3 ETag is then its WebDAV ETag, see [`ObjectMeta::etag_or`]).
    pub s3_etag: Option<String>,
    /// The object ACL is `public-read`.
    pub public_read: bool,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `Content-Language`.
    pub content_language: Option<String>,
    /// `Cache-Control`.
    pub cache_control: Option<String>,
    /// `Expires`, as sent.
    pub expires: Option<String>,
    /// `x-amz-meta-*`: names in lowercase without the prefix.
    pub user_meta: BTreeMap<String, String>,
    /// The `x-amz-checksum-*` the upload carried.
    pub checksum: Option<Checksum>,
}

impl ObjectMeta {
    /// The S3 ETag of a version whose WebDAV ETag is `dav_etag`.
    pub fn etag_or<'a>(&'a self, dav_etag: &'a str) -> &'a str {
        self.s3_etag.as_deref().unwrap_or(dav_etag)
    }
}

/// A checksum an upload carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1` or `SHA256`.
    pub algorithm: String,
    /// The value as sent (base64).
    pub value: String,
}

#[derive(FromRow)]
struct MetaRow {
    s3_etag: Option<String>,
    public_read: bool,
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_disposition: Option<String>,
    content_language: Option<String>,
    cache_control: Option<String>,
    expires: Option<String>,
    user_meta: String,
    checksum_algorithm: Option<String>,
    checksum_value: Option<String>,
}

impl From<MetaRow> for ObjectMeta {
    fn from(row: MetaRow) -> Self {
        Self {
            s3_etag: row.s3_etag,
            public_read: row.public_read,
            content_type: row.content_type,
            content_encoding: row.content_encoding,
            content_disposition: row.content_disposition,
            content_language: row.content_language,
            cache_control: row.cache_control,
            expires: row.expires,
            // Only the MetaStore writes this column, always from a map; an unreadable value
            // would mean a damaged database, and losing user metadata beats failing reads.
            user_meta: serde_json::from_str(&row.user_meta).unwrap_or_default(),
            checksum: row
                .checksum_algorithm
                .zip(row.checksum_value)
                .map(|(algorithm, value)| Checksum { algorithm, value }),
        }
    }
}

/// Inserts or replaces the `object_meta` row of `file_id` inside `tx`.
pub(super) async fn store_object_meta(
    tx: &mut db::Tx,
    file_id: i64,
    meta: &ObjectMeta,
) -> Result<()> {
    let user_meta =
        serde_json::to_string(&meta.user_meta).unwrap_or_else(|_| unreachable!("a string map"));
    sqlx::query(
        "INSERT OR REPLACE INTO object_meta (file_id, s3_etag, public_read, content_type, \
         content_encoding, content_disposition, content_language, cache_control, expires, \
         user_meta, checksum_algorithm, checksum_value) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .bind(file_id)
    .bind(meta.s3_etag.as_deref())
    .bind(meta.public_read)
    .bind(meta.content_type.as_deref())
    .bind(meta.content_encoding.as_deref())
    .bind(meta.content_disposition.as_deref())
    .bind(meta.content_language.as_deref())
    .bind(meta.cache_control.as_deref())
    .bind(meta.expires.as_deref())
    .bind(user_meta)
    .bind(meta.checksum.as_ref().map(|c| c.algorithm.as_str()))
    .bind(meta.checksum.as_ref().map(|c| c.value.as_str()))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Deletes the `object_meta` row of `file_id` inside `tx`, if there is one.
pub(super) async fn clear_object_meta(tx: &mut db::Tx, file_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM object_meta WHERE file_id = ?1")
        .bind(file_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// What [`MetaStore::list_objects`] lists.
#[derive(Debug, Clone, Copy)]
pub struct ObjectQuery<'a> {
    /// The folder keys are relative to (a bucket's folder).
    pub root: &'a RelPath,
    /// Only keys that start with this.
    pub prefix: &'a str,
    /// Keys whose part after `prefix` contains this are rolled up into one common prefix: the
    /// key up to and including the first occurrence. `None` or empty: no roll-up.
    pub delimiter: Option<&'a str>,
    /// Only what sorts after this key. When it lies inside a common prefix, every key of that
    /// common prefix is skipped, so a listing can continue after a common prefix it returned.
    pub start_after: Option<&'a str>,
    /// At most this many entries, objects and common prefixes together.
    pub max_entries: usize,
}

/// One entry of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListEntry {
    /// A file.
    Object(ListedObject),
    /// A common prefix, with the delimiter at its end.
    CommonPrefix(String),
}

impl ListEntry {
    /// The key or the common prefix: where a listing that ends here continues.
    pub fn marker(&self) -> &str {
        match self {
            Self::Object(object) => &object.key,
            Self::CommonPrefix(prefix) => prefix,
        }
    }
}

/// A file of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedObject {
    /// The key: the file's path relative to the query's root.
    pub key: String,
    /// The file's row.
    pub file: FileRow,
    /// The S3 ETag stored for this version, if it was written through the S3 API.
    pub s3_etag: Option<String>,
}

impl ListedObject {
    /// The S3 ETag: the stored one, or else the WebDAV ETag.
    pub fn etag(&self) -> &str {
        self.s3_etag.as_deref().unwrap_or(&self.file.etag)
    }
}

/// The result of [`MetaStore::list_objects`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectListing {
    /// Objects and common prefixes in S3 order.
    pub entries: Vec<ListEntry>,
    /// More entries follow the last one.
    pub truncated: bool,
}

/// The smallest string greater than every string that starts with `prefix`, or `None` if there
/// is none (an empty prefix, or one of only U+10FFFF).
///
/// The last character is replaced by the next Unicode scalar value (dropping trailing
/// U+10FFFF first). UTF-8 byte order is code point order, so with `BINARY` collation
/// `s >= prefix AND s < prefix_successor(prefix)` holds exactly the strings that start with
/// `prefix`. For a prefix ending in `/` this is [`super::descendant_bounds`]'s upper bound.
pub fn prefix_successor(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(last) = chars.pop() {
        let next = match last {
            '\u{D7FF}' => Some('\u{E000}'),
            last => char::from_u32(u32::from(last) + 1),
        };
        if let Some(next) = next {
            chars.push(next);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// The lower end of a scan.
#[derive(Debug, Clone)]
enum Start {
    Including(String),
    After(String),
}

#[derive(FromRow)]
struct ListedRow {
    #[sqlx(flatten)]
    file: Row,
    s3_etag: Option<String>,
}

impl MetaStore {
    /// The S3 metadata of the current version of file `file_id`, if it has any.
    pub async fn object_meta(&self, file_id: i64) -> Result<Option<ObjectMeta>> {
        let row: Option<MetaRow> = sqlx::query_as(
            "SELECT s3_etag, public_read, content_type, content_encoding, content_disposition, \
             content_language, cache_control, expires, user_meta, checksum_algorithm, \
             checksum_value FROM object_meta WHERE file_id = ?1",
        )
        .bind(file_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(ObjectMeta::from))
    }

    /// Sets or clears the `public-read` ACL of the version of file `file_id` whose WebDAV ETag
    /// is `etag`. Returns `false`, and changes nothing, when the file is gone, is a directory
    /// or has been written since: an ACL always applies to the version it was set for.
    ///
    /// The ACL is not content, so ETags stay the same and nothing is logged.
    pub async fn set_object_public(&self, file_id: i64, etag: &str, public: bool) -> Result<bool> {
        let mut tx = db::begin_immediate(self.pool()).await?;
        // The WHERE clause also tells SQLite's parser that ON CONFLICT belongs to the INSERT.
        let changed = sqlx::query(
            "INSERT INTO object_meta (file_id, public_read) \
             SELECT id, ?3 FROM files WHERE id = ?1 AND etag = ?2 AND is_dir = 0 \
             ON CONFLICT (file_id) DO UPDATE SET public_read = excluded.public_read",
        )
        .bind(file_id)
        .bind(etag)
        .bind(public)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(changed > 0)
    }

    /// Of `owner`'s files `file_ids`, those whose recorded version has the `public-read` ACL,
    /// each with the WebDAV ETag of that version (the ACL holds only while the file on disk is
    /// still that version).
    pub async fn public_objects(
        &self,
        owner: i64,
        file_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, String>> {
        if file_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let ids = serde_json::to_string(file_ids).unwrap_or_else(|_| unreachable!("numbers"));
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT f.id, f.etag FROM object_meta o JOIN files f ON f.id = o.file_id \
             WHERE o.public_read = 1 AND f.owner_id = ?1 AND f.is_dir = 0 \
             AND o.file_id IN (SELECT value FROM json_each(?2))",
        )
        .bind(owner)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Lists `owner`'s files below `query.root` in S3 key order, with S3's prefix, delimiter
    /// and start-after semantics (see the module documentation).
    pub async fn list_objects(&self, owner: i64, query: ObjectQuery<'_>) -> Result<ObjectListing> {
        let base = if query.root.is_root() {
            String::new()
        } else {
            format!("{}/", query.root.as_str())
        };
        let delimiter = query.delimiter.filter(|d| !d.is_empty());
        let full_prefix = format!("{base}{}", query.prefix);
        let upper = prefix_successor(&full_prefix);

        let mut from = Start::Including(full_prefix.clone());
        if let Some(after) = query.start_after {
            let full_after = format!("{base}{after}");
            if full_after >= full_prefix {
                from = Start::After(full_after);
                // Inside a common prefix: continue after all of its keys.
                if let Some(group) = after
                    .strip_prefix(query.prefix)
                    .zip(delimiter)
                    .and_then(|(rest, d)| rest.find(d).map(|at| at + d.len()))
                    .map(|end| &after[..query.prefix.len() + end])
                {
                    match prefix_successor(&format!("{base}{group}")) {
                        Some(next) => from = Start::Including(next),
                        None => return Ok(ObjectListing::default()),
                    }
                }
            }
        }

        // One more than asked for tells whether the listing is truncated.
        let want = query.max_entries.saturating_add(1);
        let mut entries = Vec::new();
        'scan: while entries.len() < want {
            let limit = want - entries.len();
            let rows = self
                .scan_files(owner, &from, upper.as_deref(), limit)
                .await?;
            let exhausted = rows.len() < limit;
            for row in rows {
                let file = FileRow::from(row.file);
                let Some(key) = file.rel_path.as_str().strip_prefix(&base) else {
                    // The range guarantees the prefix; stay safe if it ever did not.
                    continue;
                };
                let group_end = delimiter.and_then(|d| {
                    key.get(query.prefix.len()..)
                        .and_then(|rest| rest.find(d))
                        .map(|at| query.prefix.len() + at + d.len())
                });
                if let Some(end) = group_end {
                    let group = key[..end].to_owned();
                    let next = prefix_successor(&format!("{base}{group}"));
                    entries.push(ListEntry::CommonPrefix(group));
                    match next {
                        // Skip the rest of the group with a fresh, indexed scan.
                        Some(next) => {
                            from = Start::Including(next);
                            continue 'scan;
                        }
                        None => break 'scan,
                    }
                }
                from = Start::After(file.rel_path.as_str().to_owned());
                entries.push(ListEntry::Object(ListedObject {
                    key: key.to_owned(),
                    file,
                    s3_etag: row.s3_etag,
                }));
            }
            if exhausted {
                break;
            }
        }
        let truncated = entries.len() > query.max_entries;
        entries.truncate(query.max_entries);
        Ok(ObjectListing { entries, truncated })
    }

    /// Up to `limit` file rows of `owner` from `from` to before `upper`, in `rel_path` order.
    async fn scan_files(
        &self,
        owner: i64,
        from: &Start,
        upper: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedRow>> {
        let (op, start) = match from {
            Start::Including(start) => (">=", start),
            Start::After(start) => (">", start),
        };
        // Separate statements with and without an upper bound: `?3 IS NULL OR rel_path < ?3`
        // would keep SQLite from ending the index range scan there.
        let upper_clause = if upper.is_some() {
            "AND f.rel_path < ?3"
        } else {
            ""
        };
        let sql = format!(
            "SELECT f.id, f.rel_path, f.is_dir, f.etag, f.mtime_ns, f.size, f.favorite, \
             f.creation_time, o.s3_etag FROM files f \
             LEFT JOIN object_meta o ON o.file_id = f.id \
             WHERE f.owner_id = ?1 AND f.rel_path {op} ?2 {upper_clause} AND f.is_dir = 0 \
             ORDER BY f.rel_path LIMIT ?4"
        );
        let rows = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .bind(start.as_str())
            .bind(upper.unwrap_or_default())
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(self.pool())
            .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successors_bound_exactly_the_strings_with_the_prefix() {
        assert_eq!(prefix_successor("a/").as_deref(), Some("a0"));
        assert_eq!(prefix_successor("ab").as_deref(), Some("ac"));
        assert_eq!(prefix_successor("a\u{D7FF}").as_deref(), Some("a\u{E000}"));
        assert_eq!(prefix_successor("a\u{10FFFF}").as_deref(), Some("b"));
        assert_eq!(prefix_successor("é").as_deref(), Some("ê"));
        assert_eq!(prefix_successor(""), None);
        assert_eq!(prefix_successor("\u{10FFFF}\u{10FFFF}"), None);
        for (prefix, inside, outside) in [
            ("a/", "a/\u{10FFFF}z", "a0"),
            ("ab", "abzzz", "ac"),
            ("a\u{10FFFF}", "a\u{10FFFF}\u{10FFFF}", "b"),
        ] {
            let next = prefix_successor(prefix).unwrap();
            assert!(inside.as_bytes() >= prefix.as_bytes() && inside.as_bytes() < next.as_bytes());
            assert!(outside.as_bytes() >= next.as_bytes());
        }
    }
}
