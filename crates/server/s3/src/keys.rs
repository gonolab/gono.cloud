//! Object keys as paths of the tree, and their encodings in listings.
//!
//! A key is a path relative to the bucket's folder, split at `/`. Keys the tree cannot hold are
//! refused instead of being rewritten:
//!
//! - every segment must be a valid [`RelPath`] segment: not empty (no `a//b`, no leading `/`),
//!   not `.` or `..`, without NUL, at most 255 bytes;
//! - and in Unicode NFC. The tree stores NFC names; silently normalizing a key would make a
//!   listing return other bytes than were written, and sync tools would upload again forever
//!   or, when deleting, remove what they had just uploaded.
//!
//! A key that ends in `/` names a folder (an S3 "folder marker").

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gono_server_core::{
    RelPath,
    path::{PathError, normalize_segment},
};

/// Longest key S3 accepts, in bytes.
pub const MAX_KEY_BYTES: usize = 1024;

/// What a key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A file: the client path (bucket name, then the key's segments).
    File(RelPath),
    /// A folder (the key ends in `/`).
    Folder(RelPath),
}

impl Target {
    /// The client path.
    pub fn path(&self) -> &RelPath {
        match self {
            Self::File(path) | Self::Folder(path) => path,
        }
    }
}

/// Why a key cannot be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Longer than [`MAX_KEY_BYTES`].
    TooLong,
    /// A segment breaks the path rules; the message says which.
    Invalid(&'static str),
}

/// The target of `key` in the bucket `bucket` (whose name is a valid path segment).
pub fn target(bucket: &str, key: &str) -> Result<Target, KeyError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(KeyError::TooLong);
    }
    if key.is_empty() {
        return Err(KeyError::Invalid("the key is empty"));
    }
    let (body, folder) = match key.strip_suffix('/') {
        Some(body) => (body, true),
        None => (key, false),
    };
    if body.is_empty() {
        return Err(KeyError::Invalid("the key is only a slash"));
    }
    let mut path = RelPath::parse(bucket).map_err(|_| KeyError::Invalid("bad bucket name"))?;
    for segment in body.split('/') {
        let normalized = normalize_segment(segment.as_bytes()).map_err(|err| {
            KeyError::Invalid(match err {
                PathError::Empty => "the key contains an empty segment ('//' or a leading '/')",
                PathError::DotSegment => "the key contains a '.' or '..' segment",
                PathError::Nul => "the key contains a NUL character",
                PathError::TooLong => "a segment of the key is longer than 255 bytes",
                PathError::Slash | PathError::NotUtf8 => "the key is not a valid path",
            })
        })?;
        if normalized != segment {
            return Err(KeyError::Invalid(
                "the key is not in Unicode NFC; the server stores names in NFC only",
            ));
        }
        path = path.join(&normalized);
    }
    Ok(if folder {
        Target::Folder(path)
    } else {
        Target::File(path)
    })
}

/// `value` percent-encoded for `encoding-type=url` listings: everything but unreserved
/// characters and `/` is encoded, so clients decoding with either `unquote` or `unquote_plus`
/// get the key back.
pub fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The continuation token that resumes a listing after `marker`.
pub fn continuation_token(marker: &str) -> String {
    URL_SAFE_NO_PAD.encode(marker)
}

/// The marker a continuation token resumes after; `None` if it is not one of ours.
pub fn marker_of_token(token: &str) -> Option<String> {
    String::from_utf8(URL_SAFE_NO_PAD.decode(token).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_become_paths_below_the_bucket() {
        assert_eq!(
            target("photos", "2026/a.jpg").unwrap(),
            Target::File(RelPath::parse("photos/2026/a.jpg").unwrap())
        );
        assert_eq!(
            target("photos", "2026/").unwrap(),
            Target::Folder(RelPath::parse("photos/2026").unwrap())
        );
        assert_eq!(
            target("photos", "a b+c%d").unwrap().path().as_str(),
            "photos/a b+c%d"
        );
    }

    #[test]
    fn keys_the_tree_cannot_hold_are_refused() {
        for bad in ["", "/", "/a", "a//b", "a/./b", "../a", "a/..", "a\0b", "//"] {
            assert!(
                matches!(target("b", bad), Err(KeyError::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(target("b", &format!("{}/x", "s".repeat(256))).is_err());
        assert_eq!(target("b", &"k".repeat(1025)), Err(KeyError::TooLong));
        // NFD (e + combining acute) is refused, NFC accepted.
        assert!(target("b", "Cafe\u{301}.txt").is_err());
        assert!(target("b", "Caf\u{e9}.txt").is_ok());
    }

    #[test]
    fn url_encoding_leaves_no_plus_or_percent_behind() {
        assert_eq!(url_encode("a b+c%d/é"), "a%20b%2Bc%25d/%C3%A9");
        assert_eq!(url_encode("plain-key_1.txt~"), "plain-key_1.txt~");
    }

    #[test]
    fn tokens_round_trip() {
        for marker in ["", "a/b", "é/ü/€", "a+b=c"] {
            assert_eq!(
                marker_of_token(&continuation_token(marker)).as_deref(),
                Some(marker)
            );
        }
        assert_eq!(marker_of_token("not base64!"), None);
    }
}
