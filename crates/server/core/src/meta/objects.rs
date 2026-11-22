//! S3 views of the `files` table: object metadata (`object_meta`) and listings in S3 key order.
//!
//! A bucket is a folder of its owner's tree; its objects are the files below that folder, and
//! an object's key is the file's path relative to the folder **as S3 spelled it**
//! ([`FileRow::spelled`]: `s3_path`, or `rel_path` when S3 wrote nothing else; S3 keys need not
//! be in NFC, the tree's names are). The S3 API itself lives in another crate; this module holds
//! what depends on the metadata model.
//!
//! # Listing order
//!
//! S3 lists keys in the byte order of their UTF-8 encoding. The spelled paths use `BINARY`
//! collation, which is that order, and stripping the folder's spelled prefix keeps it
//! (`files_s3_listing` indexes them). [`MetaStore::list_objects`] therefore reads file rows in
//! that order and never derives common prefixes from directory rows: the folder `a` sorts before the file `a-b`, while S3 orders the common prefix
//! `a/` after the key `a-b` (`-` is 0x2D, `/` is 0x2F). Common prefixes come from the first file
//! below them, and the scan then jumps past all their keys with one indexed seek
//! ([`prefix_successor`]). Directories without files never show up, as in S3.

use std::collections::BTreeMap;

use sqlx::FromRow;

use super::store::{FileRow, MetaStore, Row};
use crate::{
    db::{self, Backend, Flag, Text},
    error::Result,
    path::RelPath,
};

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
    /// The object's tags (`x-amz-tagging`).
    pub tags: BTreeMap<String, String>,
    /// The `x-amz-checksum-*` the upload carried, or the checksum of a multipart upload.
    pub checksum: Option<Checksum>,
    /// The parts of an object written by a multipart upload, in order (empty otherwise).
    /// Written with the metadata; [`MetaStore::object_meta`] leaves them out, and
    /// [`MetaStore::object_parts`] reads them.
    pub parts: Vec<ObjectPart>,
}

impl ObjectMeta {
    /// The S3 ETag of a version whose S3 ETag would otherwise be `fallback` (the MD5 of its
    /// content, or its WebDAV ETag).
    pub fn etag_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.s3_etag.as_deref().unwrap_or(fallback)
    }
}

/// A checksum an upload carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1` or `SHA256`.
    pub algorithm: String,
    /// The value as sent (base64); for a composite checksum followed by `-<parts>`.
    pub value: String,
    /// A checksum of the parts' checksums (S3's `COMPOSITE`), not of the content
    /// (`FULL_OBJECT`).
    pub composite: bool,
}

/// A part of an object written by a multipart upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPart {
    /// Length in bytes.
    pub size: u64,
    /// The part's checksum (base64) in the object's checksum algorithm, if it has one.
    pub checksum: Option<String>,
}

#[derive(FromRow)]
struct MetaRow {
    s3_etag: Option<String>,
    #[sqlx(try_from = "Flag")]
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
    checksum_type: Option<String>,
    tags: String,
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
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            checksum: row
                .checksum_algorithm
                .zip(row.checksum_value)
                .map(|(algorithm, value)| Checksum {
                    algorithm,
                    value,
                    composite: row.checksum_type.as_deref() == Some("COMPOSITE"),
                }),
            parts: Vec::new(),
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
    let tags = serde_json::to_string(&meta.tags).unwrap_or_else(|_| unreachable!("a string map"));
    // Delete and insert, as `INSERT OR REPLACE` would, in SQL both backends speak. The parts of
    // the replaced version go with its row (`ON DELETE CASCADE`).
    sqlx::query("DELETE FROM object_meta WHERE file_id = ?")
        .bind(file_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO object_meta (file_id, s3_etag, public_read, content_type, \
         content_encoding, content_disposition, content_language, cache_control, expires, \
         user_meta, checksum_algorithm, checksum_value, checksum_type, tags, written_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(meta.checksum.as_ref().map(|c| {
        if c.composite {
            "COMPOSITE"
        } else {
            "FULL_OBJECT"
        }
    }))
    .bind(tags)
    .bind(db::unix_now())
    .execute(&mut **tx)
    .await?;
    for (number, part) in (1_i64..).zip(&meta.parts) {
        sqlx::query(
            "INSERT INTO object_parts (file_id, part_number, size, checksum) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(file_id)
        .bind(number)
        .bind(i64::try_from(part.size).unwrap_or(i64::MAX))
        .bind(part.checksum.as_deref())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Deletes the `object_meta` row of `file_id` inside `tx`, if there is one.
pub(super) async fn clear_object_meta(tx: &mut db::Tx, file_id: i64) -> Result<()> {
    // Its parts go with it (`ON DELETE CASCADE`).
    sqlx::query("DELETE FROM object_meta WHERE file_id = ?")
        .bind(file_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// A file that lifecycle rules may expire: written through the S3 API, still that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryCandidate {
    /// The file's row.
    pub file: FileRow,
    /// Its tags.
    pub tags: BTreeMap<String, String>,
    /// When the version was written through the S3 API, UNIX seconds.
    pub written_at: i64,
}

#[derive(FromRow)]
struct CandidateRow {
    #[sqlx(flatten)]
    file: Row,
    tags: String,
    written_at: i64,
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
    /// The S3 ETag: the stored one, else the MD5 of the content, else the WebDAV ETag.
    pub fn etag(&self) -> String {
        self.s3_etag
            .clone()
            .or_else(|| self.file.md5_hex())
            .unwrap_or_else(|| self.file.etag.clone())
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
             checksum_value, checksum_type, tags FROM object_meta WHERE file_id = ?",
        )
        .bind(file_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(ObjectMeta::from))
    }

    /// When the version of file `file_id` its S3 metadata describes was written through the S3
    /// API (UNIX seconds), if it was: what lifecycle rules count its age from. `None` also for
    /// a version that only got an ACL or tags (it has no S3 ETag then), as
    /// [`Self::expiry_candidates`] leaves those out. Like [`Self::object_meta`], the caller
    /// checks that the metadata belongs to the file's current version.
    pub async fn written_at(&self, file_id: i64) -> Result<Option<i64>> {
        let written_at: Option<Option<i64>> = sqlx::query_scalar(
            "SELECT written_at FROM object_meta WHERE file_id = ? AND s3_etag IS NOT NULL",
        )
        .bind(file_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(written_at.flatten())
    }

    /// Up to `limit` files of `owner` below the folder `folder` whose current version was
    /// written through the S3 API at or before `written_before` (any time if `None`), after
    /// file id `after`, by id: what the lifecycle rules of a bucket on that folder judge.
    pub async fn expiry_candidates(
        &self,
        owner: i64,
        folder: &RelPath,
        written_before: Option<i64>,
        after: i64,
        limit: u32,
    ) -> Result<Vec<ExpiryCandidate>> {
        let (lower, upper) = super::descendant_bounds(folder.as_str()).unwrap_or_default();
        let rows: Vec<CandidateRow> = sqlx::query_as(
            "SELECT f.id, f.rel_path, f.is_dir, f.etag, f.mtime_ns, f.size, f.favorite, \
             f.creation_time, f.s3_path, f.md5, o.tags, o.written_at \
             FROM files f JOIN object_meta o ON o.file_id = f.id \
             WHERE f.owner_id = ? AND f.is_dir = 0 AND f.rel_path >= ? AND f.rel_path < ? \
             AND o.s3_etag IS NOT NULL AND o.written_at IS NOT NULL \
             AND (? IS NULL OR o.written_at <= ?) AND f.id > ? ORDER BY f.id LIMIT ?",
        )
        .bind(owner)
        .bind(lower)
        .bind(upper)
        .bind(written_before)
        .bind(written_before)
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| ExpiryCandidate {
                file: FileRow::from(row.file),
                tags: serde_json::from_str(&row.tags).unwrap_or_default(),
                written_at: row.written_at,
            })
            .collect())
    }

    /// The parts of file `file_id`'s current version, in order, if a multipart upload wrote
    /// it (empty otherwise). Like [`Self::object_meta`], they describe the version the S3 API
    /// wrote, which the caller checks.
    pub async fn object_parts(&self, file_id: i64) -> Result<Vec<ObjectPart>> {
        let rows: Vec<(i64, Option<String>)> = sqlx::query_as(
            "SELECT size, checksum FROM object_parts WHERE file_id = ? ORDER BY part_number",
        )
        .bind(file_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(size, checksum)| ObjectPart {
                size: u64::try_from(size).unwrap_or(0),
                checksum,
            })
            .collect())
    }

    /// Sets the tags of the version of file `file_id` whose WebDAV ETag is `etag` (empty: none).
    /// Returns `false`, and changes nothing, when the file is gone, is a directory or has been
    /// written since. Tags are not content: ETags stay the same and nothing is logged.
    pub async fn set_object_tags(
        &self,
        file_id: i64,
        etag: &str,
        tags: &BTreeMap<String, String>,
    ) -> Result<bool> {
        let tags = serde_json::to_string(tags).unwrap_or_else(|_| unreachable!("a string map"));
        let mut tx = db::begin_immediate(self.pool()).await?;
        // The WHERE clause also tells SQLite's parser that ON CONFLICT belongs to the INSERT.
        // MySQL counts an updated row twice, so any count means the version was there.
        let changed = sqlx::query(tx.backend().pick(
            "INSERT INTO object_meta (file_id, tags, user_meta) \
             SELECT id, ?, '{}' FROM files WHERE id = ? AND etag = ? AND is_dir = 0 \
             ON CONFLICT (file_id) DO UPDATE SET tags = excluded.tags",
            "INSERT INTO object_meta (file_id, tags, user_meta) \
             SELECT id, ?, '{}' FROM files WHERE id = ? AND etag = ? AND is_dir = 0 \
             ON DUPLICATE KEY UPDATE tags = VALUES(tags)",
        ))
        .bind(tags)
        .bind(file_id)
        .bind(etag)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(changed > 0)
    }

    /// Sets or clears the `public-read` ACL of the version of file `file_id` whose WebDAV ETag
    /// is `etag`. Returns `false`, and changes nothing, when the file is gone, is a directory
    /// or has been written since: an ACL always applies to the version it was set for.
    ///
    /// The ACL is not content, so ETags stay the same and nothing is logged.
    pub async fn set_object_public(&self, file_id: i64, etag: &str, public: bool) -> Result<bool> {
        let mut tx = db::begin_immediate(self.pool()).await?;
        // The WHERE clause also tells SQLite's parser that ON CONFLICT belongs to the INSERT.
        let changed = sqlx::query(tx.backend().pick(
            "INSERT INTO object_meta (file_id, public_read, user_meta, tags) \
             SELECT id, ?, '{}', '{}' FROM files WHERE id = ? AND etag = ? AND is_dir = 0 \
             ON CONFLICT (file_id) DO UPDATE SET public_read = excluded.public_read",
            "INSERT INTO object_meta (file_id, public_read, user_meta, tags) \
             SELECT id, ?, '{}', '{}' FROM files WHERE id = ? AND etag = ? AND is_dir = 0 \
             ON DUPLICATE KEY UPDATE public_read = VALUES(public_read)",
        ))
        .bind(public)
        .bind(file_id)
        .bind(etag)
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
        let mut found = std::collections::HashMap::new();
        for chunk in file_ids.chunks(db::MAX_LIST) {
            let sql = format!(
                "SELECT f.id, f.etag FROM object_meta o JOIN files f ON f.id = o.file_id \
                 WHERE o.public_read = 1 AND f.owner_id = ? AND f.is_dir = 0 \
                 AND o.file_id IN ({})",
                db::placeholders(chunk.len())
            );
            let mut query =
                sqlx::query_as::<_, (i64, String)>(sqlx::AssertSqlSafe(sql)).bind(owner);
            for id in chunk {
                query = query.bind(id);
            }
            found.extend(query.fetch_all(self.pool()).await?);
        }
        Ok(found)
    }

    /// Of `owner`'s entries `file_ids`, those that S3 spells otherwise than their path, with
    /// that spelling ([`FileRow::s3_path`]).
    pub async fn spellings(
        &self,
        owner: i64,
        file_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, String>> {
        let mut found = std::collections::HashMap::new();
        for chunk in file_ids.chunks(db::MAX_LIST) {
            let sql = format!(
                "SELECT id, s3_path FROM files WHERE owner_id = ? AND s3_path IS NOT NULL \
                 AND id IN ({})",
                db::placeholders(chunk.len())
            );
            let mut query = sqlx::query_as::<_, (i64, Text)>(sqlx::AssertSqlSafe(sql)).bind(owner);
            for id in chunk {
                query = query.bind(id);
            }
            found.extend(
                query
                    .fetch_all(self.pool())
                    .await?
                    .into_iter()
                    .map(|(id, spelled)| (id, spelled.0)),
            );
        }
        Ok(found)
    }

    /// Lists `owner`'s files below `query.root` in S3 key order, with S3's prefix, delimiter
    /// and start-after semantics (see the module documentation).
    pub async fn list_objects(&self, owner: i64, query: ObjectQuery<'_>) -> Result<ObjectListing> {
        let base = if query.root.is_root() {
            String::new()
        } else {
            let root = self.get(owner, query.root).await?;
            let spelled = root
                .as_ref()
                .map_or(query.root.as_str(), |row| row.spelled());
            format!("{spelled}/")
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
                let spelled = file.spelled().to_owned();
                let Some(key) = spelled.strip_prefix(&base) else {
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
                from = Start::After(spelled.clone());
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

    /// Up to `limit` file rows of `owner` from `from` to before `upper`, in the order of their
    /// spelled paths (the expression and the condition of the index `files_s3_listing`; MySQL
    /// indexes the generated column `s3_key`, which is that expression).
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
        let key = Backend::of(self.pool()).pick("COALESCE(f.s3_path, f.rel_path)", "f.s3_key");
        // Separate statements with and without an upper bound: `? IS NULL OR ... < ?` would
        // keep SQLite from ending the index range scan there.
        let upper_clause = if upper.is_some() {
            format!("AND {key} < ?")
        } else {
            String::new()
        };
        let sql = format!(
            "SELECT f.id, f.rel_path, f.is_dir, f.etag, f.mtime_ns, f.size, f.favorite, \
             f.creation_time, f.s3_path, f.md5, o.s3_etag FROM files f \
             LEFT JOIN object_meta o ON o.file_id = f.id \
             WHERE f.owner_id = ? AND f.is_dir = 0 AND {key} {op} ? {upper_clause} \
             ORDER BY {key} LIMIT ?"
        );
        let mut query = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .bind(start.as_str());
        if let Some(upper) = upper {
            query = query.bind(upper);
        }
        let rows = query
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
