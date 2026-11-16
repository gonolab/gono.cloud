//! Lifecycle rules: objects that expire, and multipart uploads that are given up.
//!
//! A bucket's rules come with `PutBucketLifecycleConfiguration` (a key with full access to the
//! bucket) and are stored as JSON (`s3_buckets.lifecycle`). Supported: `Expiration` after
//! `Days` or on a `Date`, and `AbortIncompleteMultipartUpload` after `DaysAfterInitiation`,
//! each rule filtered by key prefix, tags and object size. Transitions and everything about
//! versions answer `NotImplemented` (no bucket ever has versions; an
//! `ExpiredObjectDeleteMarker` is accepted and does nothing, as there are no delete markers).
//!
//! Unlike S3, rules expire only files whose current version was written through the S3 API:
//! a bucket is a folder of its owner's tree, and what WebDAV and the Nextcloud clients put there
//! is never deleted by a rule. Age counts from when that version was written to the server
//! (`object_meta.written_at`), never from the modification time, which clients set; with `Days`
//! an object expires at the first midnight UTC after that many days, as in S3.
//!
//! [`apply`] runs the rules of every bucket; the server's janitor calls it every few minutes.
//! It deletes a file only while it is still the version it judged and not locked by a WebDAV
//! client, and writes an audit record per bucket and pass that deleted something. Deleting is
//! permanent: there is no trash.

use std::{collections::BTreeMap, sync::Arc};

use gono_server_core::{
    RelPath, audit,
    audit::{Actor, Record},
    s3::{self, Bucket},
};
use gono_server_dav::{Identity, Mount, locks};
use rand::RngExt as _;
use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::S3State;

/// Most rules of a bucket, as in S3.
const MAX_RULES: usize = 1000;
/// Seconds of a day.
const DAY: i64 = 24 * 60 * 60;
/// Candidates read per database query.
const BATCH: u32 = 500;

/// One rule as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rule {
    id: String,
    enabled: bool,
    /// The rule named its prefix in the old `Prefix` element instead of a `Filter`.
    #[serde(default)]
    legacy_prefix: bool,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    tags: BTreeMap<String, String>,
    size_greater_than: Option<i64>,
    size_less_than: Option<i64>,
    expiration_days: Option<i32>,
    /// UNIX seconds, a midnight UTC.
    expiration_date: Option<i64>,
    expired_object_delete_marker: Option<bool>,
    abort_days: Option<i32>,
}

fn malformed(message: &str) -> S3Error {
    S3Error::with_message(S3ErrorCode::MalformedXML, message.to_owned())
}

fn invalid(message: &str) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidArgument, message.to_owned())
}

/// The rules of a `PutBucketLifecycleConfiguration`, checked.
pub(crate) fn from_config(config: dto::BucketLifecycleConfiguration) -> S3Result<Vec<Rule>> {
    if config.rules.is_empty() {
        return Err(malformed(
            "A lifecycle configuration needs at least one rule",
        ));
    }
    if config.rules.len() > MAX_RULES {
        return Err(malformed("At most 1000 rules are allowed"));
    }
    let mut rules: Vec<Rule> = Vec::with_capacity(config.rules.len());
    for rule in config.rules {
        let rule = from_rule(rule)?;
        if rules.iter().any(|other| other.id == rule.id) {
            return Err(invalid("Rule IDs must be unique"));
        }
        rules.push(rule);
    }
    Ok(rules)
}

fn from_rule(rule: dto::LifecycleRule) -> S3Result<Rule> {
    if rule
        .transitions
        .as_ref()
        .is_some_and(|list| !list.is_empty())
        || rule
            .noncurrent_version_transitions
            .as_ref()
            .is_some_and(|list| !list.is_empty())
        || rule.noncurrent_version_expiration.is_some()
    {
        return Err(s3_error!(
            NotImplemented,
            "Only Expiration and AbortIncompleteMultipartUpload are supported"
        ));
    }
    let id = match rule.id {
        Some(id) if id.chars().count() > 255 => {
            return Err(invalid("A rule ID is at most 255 characters"));
        }
        Some(id) if !id.is_empty() => id,
        // S3 names a rule without an ID.
        _ => format!("{:016x}", rand::rng().random::<u64>()),
    };
    let enabled = match rule.status.as_str() {
        dto::ExpirationStatus::ENABLED => true,
        dto::ExpirationStatus::DISABLED => false,
        _ => return Err(malformed("Status is Enabled or Disabled")),
    };
    let mut parsed = Rule {
        id,
        enabled,
        legacy_prefix: false,
        prefix: String::new(),
        tags: BTreeMap::new(),
        size_greater_than: None,
        size_less_than: None,
        expiration_days: None,
        expiration_date: None,
        expired_object_delete_marker: None,
        abort_days: None,
    };
    match (rule.prefix, rule.filter) {
        (Some(_), Some(_)) => return Err(malformed("A rule has a Prefix or a Filter, not both")),
        (Some(prefix), None) => {
            parsed.legacy_prefix = true;
            parsed.prefix = prefix;
        }
        (None, Some(filter)) => {
            let singles = [
                filter.prefix.is_some(),
                filter.tag.is_some(),
                filter.object_size_greater_than.is_some(),
                filter.object_size_less_than.is_some(),
                filter.and.is_some(),
            ];
            if singles.into_iter().filter(|set| *set).count() > 1 {
                return Err(malformed(
                    "A Filter names one condition; combine them with And",
                ));
            }
            let and = filter.and.unwrap_or_default();
            parsed.prefix = filter.prefix.or(and.prefix).unwrap_or_default();
            let tags = filter
                .tag
                .into_iter()
                .chain(and.tags.unwrap_or_default())
                .map(|tag| (tag.key.unwrap_or_default(), tag.value.unwrap_or_default()));
            for (key, value) in tags {
                if parsed.tags.insert(key, value).is_some() {
                    return Err(invalid("A filter names each tag key once"));
                }
            }
            parsed.size_greater_than = filter
                .object_size_greater_than
                .or(and.object_size_greater_than);
            parsed.size_less_than = filter.object_size_less_than.or(and.object_size_less_than);
            if let (Some(greater), Some(less)) = (parsed.size_greater_than, parsed.size_less_than)
                && greater >= less
            {
                return Err(invalid(
                    "ObjectSizeGreaterThan must be below ObjectSizeLessThan",
                ));
            }
        }
        (None, None) => {}
    }
    if let Some(expiration) = rule.expiration {
        if expiration.days.is_some() && expiration.date.is_some() {
            return Err(malformed("Expiration has Days or Date, not both"));
        }
        if let Some(days) = expiration.days {
            if days <= 0 {
                return Err(invalid("Expiration Days must be a positive integer"));
            }
            parsed.expiration_days = Some(days);
        }
        if let Some(date) = expiration.date {
            let date = time::OffsetDateTime::from(date).unix_timestamp();
            if date.rem_euclid(DAY) != 0 {
                return Err(invalid("Expiration Date must be at midnight UTC"));
            }
            parsed.expiration_date = Some(date);
        }
        if expiration.expired_object_delete_marker.is_some()
            && (parsed.expiration_days.is_some() || parsed.expiration_date.is_some())
        {
            return Err(invalid(
                "ExpiredObjectDeleteMarker cannot be combined with Days or Date",
            ));
        }
        parsed.expired_object_delete_marker = expiration.expired_object_delete_marker;
    }
    if let Some(abort) = rule.abort_incomplete_multipart_upload {
        let days = abort
            .days_after_initiation
            .filter(|days| *days > 0)
            .ok_or_else(|| invalid("DaysAfterInitiation must be a positive integer"))?;
        if !parsed.tags.is_empty() {
            return Err(invalid(
                "AbortIncompleteMultipartUpload cannot be combined with tag filters",
            ));
        }
        parsed.abort_days = Some(days);
    }
    if parsed.expiration_days.is_none()
        && parsed.expiration_date.is_none()
        && parsed.expired_object_delete_marker.is_none()
        && parsed.abort_days.is_none()
    {
        return Err(invalid("A rule needs an action"));
    }
    Ok(parsed)
}

/// `rules` as a `GetBucketLifecycleConfiguration` answers them.
pub(crate) fn to_config(rules: &[Rule]) -> dto::LifecycleRules {
    rules
        .iter()
        .map(|rule| {
            let tags: Vec<dto::Tag> = crate::tags::to_tag_set(&rule.tags);
            let conditions = usize::from(!rule.prefix.is_empty())
                + tags.len()
                + usize::from(rule.size_greater_than.is_some())
                + usize::from(rule.size_less_than.is_some());
            let filter = (!rule.legacy_prefix).then(|| {
                if conditions > 1 {
                    dto::LifecycleRuleFilter {
                        and: Some(dto::LifecycleRuleAndOperator {
                            prefix: (!rule.prefix.is_empty()).then(|| rule.prefix.clone()),
                            tags: (!tags.is_empty()).then(|| tags.clone()),
                            object_size_greater_than: rule.size_greater_than,
                            object_size_less_than: rule.size_less_than,
                        }),
                        ..Default::default()
                    }
                } else {
                    dto::LifecycleRuleFilter {
                        prefix: Some(rule.prefix.clone()).filter(|prefix| !prefix.is_empty()),
                        tag: tags.first().cloned(),
                        object_size_greater_than: rule.size_greater_than,
                        object_size_less_than: rule.size_less_than,
                        ..Default::default()
                    }
                }
            });
            let expiration = (rule.expiration_days.is_some()
                || rule.expiration_date.is_some()
                || rule.expired_object_delete_marker.is_some())
            .then(|| dto::LifecycleExpiration {
                days: rule.expiration_days,
                date: rule.expiration_date.and_then(|date| {
                    time::OffsetDateTime::from_unix_timestamp(date)
                        .ok()
                        .map(dto::Timestamp::from)
                }),
                expired_object_delete_marker: rule.expired_object_delete_marker,
            });
            dto::LifecycleRule {
                id: Some(rule.id.clone()),
                status: dto::ExpirationStatus::from(
                    if rule.enabled {
                        dto::ExpirationStatus::ENABLED
                    } else {
                        dto::ExpirationStatus::DISABLED
                    }
                    .to_owned(),
                ),
                prefix: rule.legacy_prefix.then(|| rule.prefix.clone()),
                filter,
                expiration,
                abort_incomplete_multipart_upload: rule.abort_days.map(|days| {
                    dto::AbortIncompleteMultipartUpload {
                        days_after_initiation: Some(days),
                    }
                }),
                noncurrent_version_expiration: None,
                noncurrent_version_transitions: None,
                transitions: None,
            }
        })
        .collect()
}

/// The rules as stored (`s3_buckets.lifecycle`).
pub(crate) fn to_stored(rules: &[Rule]) -> String {
    serde_json::to_string(rules).unwrap_or_else(|_| "[]".to_owned())
}

/// The rules of a bucket as stored; none if they cannot be read.
pub(crate) fn from_stored(stored: Option<&str>) -> Vec<Rule> {
    stored
        .and_then(|stored| serde_json::from_str(stored).ok())
        .unwrap_or_default()
}

impl Rule {
    /// Whether the rule applies to the object `key` of `size` bytes with `tags`.
    fn matches(&self, key: &str, size: u64, tags: &BTreeMap<String, String>) -> bool {
        let size = i64::try_from(size).unwrap_or(i64::MAX);
        key.starts_with(&self.prefix)
            && self
                .tags
                .iter()
                .all(|(name, value)| tags.get(name) == Some(value))
            && self.size_greater_than.is_none_or(|greater| size > greater)
            && self.size_less_than.is_none_or(|less| size < less)
    }

    /// When an object written at `written_at` (UNIX seconds) expires under this rule, if it
    /// does: after `Days`, at the next midnight UTC; on `Date`.
    fn expires_at(&self, written_at: i64) -> Option<i64> {
        if let Some(days) = self.expiration_days {
            let after = written_at.saturating_add(i64::from(days).saturating_mul(DAY));
            return Some(
                after
                    .div_euclid(DAY)
                    .saturating_add(i64::from(after.rem_euclid(DAY) != 0))
                    * DAY,
            );
        }
        self.expiration_date
    }

    /// The latest write time that may have expired by `now`: `Some(None)` for any time (a
    /// date that has come), `None` if nothing expires yet.
    fn written_before(&self, now: i64) -> Option<Option<i64>> {
        if let Some(days) = self.expiration_days {
            return Some(Some(
                now.saturating_sub(i64::from(days).saturating_mul(DAY)),
            ));
        }
        match self.expiration_date {
            Some(date) if date <= now => Some(None),
            _ => None,
        }
    }
}

/// What one pass of [`apply`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    /// Objects deleted.
    pub expired: usize,
    /// Multipart uploads given up.
    pub aborted: usize,
}

/// Applies the lifecycle rules of every bucket at `now` (UNIX seconds).
///
/// # Errors
///
/// A failure of the database; files that cannot be deleted are logged and left.
pub async fn apply(state: &S3State, now: i64) -> gono_server_core::Result<Applied> {
    let mut total = Applied::default();
    for bucket in s3::buckets_with_lifecycle(state.pool()).await? {
        let rules = from_stored(bucket.lifecycle.as_deref());
        let applied = apply_to_bucket(state, &bucket, &rules, now).await?;
        if applied != Applied::default() {
            tracing::info!(
                bucket = %bucket.name,
                expired = applied.expired,
                aborted = applied.aborted,
                "applied S3 lifecycle rules"
            );
            let record = Record::new(bucket.owner_id, "s3.lifecycle.applied", Actor::Server).details(
                json!({ "bucket": bucket.name, "expired": applied.expired, "aborted": applied.aborted }),
            );
            if let Err(err) = audit::record(state.pool(), &record, now).await {
                tracing::warn!(error = %err, "cannot write an audit record");
            }
        }
        total.expired += applied.expired;
        total.aborted += applied.aborted;
    }
    Ok(total)
}

async fn apply_to_bucket(
    state: &S3State,
    bucket: &Bucket,
    rules: &[Rule],
    now: i64,
) -> gono_server_core::Result<Applied> {
    let mut applied = Applied::default();
    let Ok(mount_path) = RelPath::parse(&bucket.name) else {
        return Ok(applied);
    };
    let identity = Arc::new(Identity {
        user_id: bucket.owner_id,
        username: bucket.owner_name.clone(),
        display_name: bucket.owner_display_name.clone(),
        app_password_id: None,
        mounts: vec![Mount {
            mount_path: mount_path.clone(),
            storage_path: bucket.folder.clone(),
            writable: true,
        }],
    });
    // Keys are paths below the folder as S3 spelled them.
    let folder_spelling = state
        .fs()
        .meta()
        .get(bucket.owner_id, &bucket.folder)
        .await?
        .map_or_else(
            || bucket.folder.as_str().to_owned(),
            |row| row.spelled().to_owned(),
        );
    for rule in rules.iter().filter(|rule| rule.enabled) {
        if let Some(written_before) = rule.written_before(now) {
            let mut after = 0;
            loop {
                let batch = state
                    .fs()
                    .meta()
                    .expiry_candidates(
                        bucket.owner_id,
                        &bucket.folder,
                        written_before,
                        after,
                        BATCH,
                    )
                    .await?;
                let Some(last) = batch.last() else {
                    break;
                };
                after = last.file.id;
                for candidate in batch {
                    let Some(key) = candidate
                        .file
                        .spelled()
                        .strip_prefix(folder_spelling.as_str())
                        .and_then(|rest| rest.strip_prefix('/'))
                    else {
                        continue;
                    };
                    if !rule.matches(key, candidate.file.size, &candidate.tags)
                        || rule
                            .expires_at(candidate.written_at)
                            .is_none_or(|at| at > now)
                    {
                        continue;
                    }
                    let Some(below) = candidate.file.rel_path.strip_prefix(&bucket.folder) else {
                        continue;
                    };
                    let locked = locks::write_conflict(
                        state.locks(),
                        bucket.owner_id,
                        &candidate.file.rel_path,
                        bucket.owner_name.as_str(),
                        &[],
                    )
                    .await?;
                    if locked.is_some() {
                        continue;
                    }
                    match state
                        .fs()
                        .delete_object_version(
                            identity.clone(),
                            &mount_path.join_path(&below),
                            &candidate.file.etag,
                        )
                        .await
                    {
                        Ok(true) => applied.expired += 1,
                        Ok(false) => {}
                        Err(err) => tracing::warn!(
                            bucket = %bucket.name,
                            key,
                            error = %err,
                            "cannot delete an expired object"
                        ),
                    }
                }
            }
        }
        if let Some(days) = rule.abort_days {
            let started_before = now.saturating_sub(i64::from(days).saturating_mul(DAY));
            for upload in s3::uploads_of_bucket(state.pool(), bucket.id).await? {
                if upload.created_at > started_before || !upload.key.starts_with(&rule.prefix) {
                    continue;
                }
                if crate::multipart::give_up(state, &upload.upload_id).await? {
                    applied.aborted += 1;
                }
            }
        }
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(xml_rules: Vec<dto::LifecycleRule>) -> S3Result<Vec<Rule>> {
        from_config(dto::BucketLifecycleConfiguration { rules: xml_rules })
    }

    fn rule() -> dto::LifecycleRule {
        dto::LifecycleRule {
            id: Some("r".into()),
            status: dto::ExpirationStatus::from_static(dto::ExpirationStatus::ENABLED),
            filter: Some(dto::LifecycleRuleFilter {
                prefix: Some("logs/".into()),
                ..Default::default()
            }),
            expiration: Some(dto::LifecycleExpiration {
                days: Some(1),
                ..Default::default()
            }),
            abort_incomplete_multipart_upload: None,
            noncurrent_version_expiration: None,
            noncurrent_version_transitions: None,
            prefix: None,
            transitions: None,
        }
    }

    fn tag(key: &str, value: &str) -> dto::Tag {
        dto::Tag {
            key: Some(key.into()),
            value: Some(value.into()),
        }
    }

    #[test]
    fn days_expire_at_the_next_midnight_utc() {
        let rules = config(vec![rule()]).unwrap();
        let rule = &rules[0];
        // Written at 2025-11-16 10:00 UTC: expires 2025-11-18 00:00 UTC.
        let written = 1_763_287_200;
        assert_eq!(rule.expires_at(written), Some(1_763_424_000));
        // Written exactly at midnight: one day later.
        assert_eq!(rule.expires_at(1_763_251_200), Some(1_763_337_600));
        assert_eq!(
            rule.written_before(1_763_424_000),
            Some(Some(1_763_337_600))
        );
    }

    #[test]
    fn rules_match_prefix_tags_and_size() {
        let mut and = rule();
        and.filter = Some(dto::LifecycleRuleFilter {
            and: Some(dto::LifecycleRuleAndOperator {
                prefix: Some("tmp/".into()),
                tags: Some(vec![tag("kind", "cache")]),
                object_size_greater_than: Some(10),
                object_size_less_than: Some(100),
            }),
            ..Default::default()
        });
        let rules = config(vec![and]).unwrap();
        let tags: BTreeMap<String, String> = [("kind".to_owned(), "cache".to_owned())].into();
        assert!(rules[0].matches("tmp/a", 50, &tags));
        assert!(!rules[0].matches("other/a", 50, &tags));
        assert!(!rules[0].matches("tmp/a", 50, &BTreeMap::new()));
        assert!(!rules[0].matches("tmp/a", 10, &tags));
        assert!(!rules[0].matches("tmp/a", 100, &tags));
        // The configuration answers as it was given.
        let back = to_config(&rules);
        let filter = back[0].filter.as_ref().unwrap().and.as_ref().unwrap();
        assert_eq!(filter.prefix.as_deref(), Some("tmp/"));
        assert_eq!(filter.tags.as_ref().unwrap().len(), 1);
        assert_eq!(from_stored(Some(&to_stored(&rules))), rules);
    }

    #[test]
    fn dates_expire_everything_that_matches() {
        let mut dated = rule();
        dated.expiration = Some(dto::LifecycleExpiration {
            date: Some(dto::Timestamp::from(
                time::OffsetDateTime::from_unix_timestamp(1_763_251_200).unwrap(),
            )),
            ..Default::default()
        });
        let rules = config(vec![dated]).unwrap();
        assert_eq!(rules[0].written_before(1_763_251_199), None);
        assert_eq!(rules[0].written_before(1_763_251_200), Some(None));
        assert_eq!(rules[0].expires_at(0), Some(1_763_251_200));
    }

    #[test]
    fn unsupported_and_malformed_rules_are_refused() {
        let code = |rules: Vec<dto::LifecycleRule>| config(rules).unwrap_err().code().clone();
        assert_eq!(code(vec![]), S3ErrorCode::MalformedXML);
        assert_eq!(
            code(vec![rule(), rule()]),
            S3ErrorCode::InvalidArgument,
            "same ID"
        );
        let mut transition = rule();
        transition.transitions = Some(vec![dto::Transition::default()]);
        assert_eq!(code(vec![transition]), S3ErrorCode::NotImplemented);
        let mut no_action = rule();
        no_action.expiration = None;
        assert_eq!(code(vec![no_action]), S3ErrorCode::InvalidArgument);
        let mut zero = rule();
        zero.expiration = Some(dto::LifecycleExpiration {
            days: Some(0),
            ..Default::default()
        });
        assert_eq!(code(vec![zero]), S3ErrorCode::InvalidArgument);
        let mut not_midnight = rule();
        not_midnight.expiration = Some(dto::LifecycleExpiration {
            date: Some(dto::Timestamp::from(
                time::OffsetDateTime::from_unix_timestamp(1_763_251_201).unwrap(),
            )),
            ..Default::default()
        });
        assert_eq!(code(vec![not_midnight]), S3ErrorCode::InvalidArgument);
        let mut both = rule();
        both.prefix = Some("x".into());
        assert_eq!(code(vec![both]), S3ErrorCode::MalformedXML);
        let mut tagged_abort = rule();
        tagged_abort.filter = Some(dto::LifecycleRuleFilter {
            tag: Some(tag("a", "b")),
            ..Default::default()
        });
        tagged_abort.abort_incomplete_multipart_upload =
            Some(dto::AbortIncompleteMultipartUpload {
                days_after_initiation: Some(1),
            });
        assert_eq!(code(vec![tagged_abort]), S3ErrorCode::InvalidArgument);
        // A rule without an ID gets one.
        let mut unnamed = rule();
        unnamed.id = None;
        assert_eq!(config(vec![unnamed]).unwrap()[0].id.len(), 16);
    }
}
