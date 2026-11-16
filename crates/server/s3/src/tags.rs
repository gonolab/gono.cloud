//! Object and bucket tags.
//!
//! Tags are key-value pairs as S3 limits them: at most 10 per object (50 per bucket), keys of
//! 1 to 128 characters, values of up to 256, each key once. An object's tags belong to its
//! version, like the rest of its S3 metadata (`object_meta.tags`): a write other than through
//! S3 drops them. They come with `PutObject` and `CreateMultipartUpload` in `x-amz-tagging`
//! (URL-encoded, `k1=v1&k2=v2`), with `CopyObject` (copied, or replaced with
//! `x-amz-tagging-directive: REPLACE`), and with `PutObjectTagging`.

use std::collections::BTreeMap;

use s3s::{S3Error, S3ErrorCode, S3Result, dto};

/// Most tags of an object.
const MAX_OBJECT_TAGS: usize = 10;
/// Most tags of a bucket.
const MAX_BUCKET_TAGS: usize = 50;
/// Longest key, in characters.
const MAX_KEY_CHARS: usize = 128;
/// Longest value, in characters.
const MAX_VALUE_CHARS: usize = 256;

fn invalid(message: impl Into<String>) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidTag, message.into())
}

/// Checks `pairs` against the limits of an object (`bucket` false) or a bucket.
fn checked(
    pairs: impl IntoIterator<Item = (String, String)>,
    bucket: bool,
) -> S3Result<BTreeMap<String, String>> {
    let max = if bucket {
        MAX_BUCKET_TAGS
    } else {
        MAX_OBJECT_TAGS
    };
    let mut tags = BTreeMap::new();
    for (key, value) in pairs {
        let length = key.chars().count();
        if length == 0 || length > MAX_KEY_CHARS {
            return Err(invalid("A tag key must be 1 to 128 characters long"));
        }
        if value.chars().count() > MAX_VALUE_CHARS {
            return Err(invalid("A tag value must be at most 256 characters long"));
        }
        if key.starts_with("aws:") {
            return Err(invalid("Tag keys starting with aws: are reserved"));
        }
        if tags.insert(key, value).is_some() {
            return Err(invalid("Cannot provide multiple tags with the same key"));
        }
    }
    if tags.len() > max {
        return Err(invalid(format!("At most {max} tags are allowed")));
    }
    Ok(tags)
}

/// The tags of an `x-amz-tagging` header (an empty header: none).
pub(crate) fn from_header(header: Option<&str>) -> S3Result<BTreeMap<String, String>> {
    let Some(header) = header.filter(|header| !header.is_empty()) else {
        return Ok(BTreeMap::new());
    };
    let decode = |text: &str| {
        let text = text.replace('+', " ");
        urlencoding_decode(&text).ok_or_else(|| invalid("The tagging header is not URL-encoded"))
    };
    let pairs = header
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((decode(key)?, decode(value)?))
        })
        .collect::<S3Result<Vec<_>>>()?;
    checked(pairs, false)
}

/// Percent-decodes `text` as UTF-8.
fn urlencoding_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = text.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// The tags of a `Tagging` document of an object (`bucket` false) or a bucket.
pub(crate) fn from_tagging(
    tagging: dto::Tagging,
    bucket: bool,
) -> S3Result<BTreeMap<String, String>> {
    checked(
        tagging
            .tag_set
            .into_iter()
            .map(|tag| (tag.key.unwrap_or_default(), tag.value.unwrap_or_default())),
        bucket,
    )
}

/// `tags` as a tag set of a response.
pub(crate) fn to_tag_set(tags: &BTreeMap<String, String>) -> dto::TagSet {
    tags.iter()
        .map(|(key, value)| dto::Tag {
            key: Some(key.clone()),
            value: Some(value.clone()),
        })
        .collect()
}

/// The tags of a bucket as stored (`s3_buckets.tags`).
pub(crate) fn from_stored(stored: Option<&str>) -> BTreeMap<String, String> {
    stored
        .and_then(|stored| serde_json::from_str(stored).ok())
        .unwrap_or_default()
}

/// The `x-amz-tagging-count` of an object with `tags`: none without tags.
pub(crate) fn count(tags: &BTreeMap<String, String>) -> Option<i32> {
    (!tags.is_empty()).then(|| i32::try_from(tags.len()).unwrap_or(i32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(tags: &BTreeMap<String, String>) -> Vec<(&str, &str)> {
        tags.iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn tagging_headers_are_url_encoded_pairs() {
        assert!(from_header(None).unwrap().is_empty());
        assert!(from_header(Some("")).unwrap().is_empty());
        let tags = from_header(Some("project=blue&empty=&a%20b=c%2Bd+e")).unwrap();
        assert_eq!(
            pairs(&tags),
            [("a b", "c+d e"), ("empty", ""), ("project", "blue")]
        );
        assert!(from_header(Some("bad=%zz")).is_err());
    }

    #[test]
    fn tags_are_limited_as_in_s3() {
        let code = |header: &str| from_header(Some(header)).unwrap_err().code().clone();
        assert_eq!(code("a=1&a=2"), S3ErrorCode::InvalidTag);
        assert_eq!(code("=value"), S3ErrorCode::InvalidTag);
        assert_eq!(
            code(&format!("{}=v", "k".repeat(129))),
            S3ErrorCode::InvalidTag
        );
        assert_eq!(
            code(&format!("k={}", "v".repeat(257))),
            S3ErrorCode::InvalidTag
        );
        assert_eq!(code("aws:x=1"), S3ErrorCode::InvalidTag);
        let eleven: Vec<String> = (0..11).map(|i| format!("k{i}=v")).collect();
        assert_eq!(code(&eleven.join("&")), S3ErrorCode::InvalidTag);
        let ten: Vec<String> = (0..10).map(|i| format!("k{i}=v")).collect();
        assert_eq!(from_header(Some(&ten.join("&"))).unwrap().len(), 10);
        let many = dto::Tagging {
            tag_set: (0..11)
                .map(|i| dto::Tag {
                    key: Some(format!("k{i}")),
                    value: Some("v".into()),
                })
                .collect(),
        };
        assert_eq!(
            from_tagging(many, true).unwrap().len(),
            11,
            "buckets take 50"
        );
    }

    #[test]
    fn stored_tags_round_trip() {
        let tags = from_header(Some("a=1&b=2")).unwrap();
        let stored = serde_json::to_string(&tags).unwrap();
        assert_eq!(from_stored(Some(&stored)), tags);
        assert!(from_stored(None).is_empty());
        assert_eq!(to_tag_set(&tags).len(), 2);
        assert_eq!(count(&tags), Some(2));
        assert_eq!(count(&BTreeMap::new()), None);
    }
}
