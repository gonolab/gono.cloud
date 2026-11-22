//! Who may do what: decided once per request, before s3s reads the request body.
//!
//! The check sorts the operation into a [`Class`] and looks up the bucket the request names.
//!
//! - **Signed requests** act as the access key's account, within the key's grants: reading
//!   needs a grant on the bucket, writing a `full` one, and creating and deleting buckets or
//!   changing a bucket's ACL a `full` grant on every bucket. Buckets of other accounts are
//!   refused like buckets the key has no grant for.
//! - **Unsigned requests** may only read: objects, if the bucket publishes them (`acl` or
//!   `public-read`; for `acl`, the operation checks the object's ACL), and listings, if the
//!   bucket allows them. Everything is private while `s3.allow_anonymous` is off or the
//!   owner's account is disabled. Every refusal is `AccessDenied`, also for buckets and objects
//!   that do not exist, so unsigned requests cannot probe for names.
//!
//! The outcome, an [`Authorized`], travels in the request's extensions to the operation.

use std::sync::Arc;

use gono_server_core::{
    Permission, RelPath, db,
    s3::{self, Anonymous, Bucket, SigningKey},
};
use gono_server_dav::{Identity, Mount};
use s3s::{
    S3Error, S3Result,
    access::{S3Access, S3AccessContext},
    s3_error,
};

use crate::state::S3State;

/// What an operation does, for the access rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// `ListBuckets`.
    Service,
    /// `CreateBucket`.
    CreateBucket,
    /// `DeleteBucket`, `PutBucketAcl`, `PutBucketPolicy`, `DeleteBucketPolicy`.
    BucketAdmin,
    /// Changing a bucket's settings that grant nothing (`PutBucketCors`, `DeleteBucketCors`):
    /// a `full` grant on the bucket.
    BucketConfig,
    /// `HeadBucket`.
    HeadBucket,
    /// Reading a bucket's settings or uploads.
    BucketRead,
    /// `ListObjects`, `ListObjectsV2`, `ListObjectVersions`.
    List,
    /// `GetObject`, `HeadObject`: what anonymous requests may do.
    ObjectRead,
    /// `GetObjectAcl`, `GetObjectTagging`: reading what a key may know about an object.
    ObjectAclRead,
    /// Every write of objects and multipart uploads.
    ObjectWrite,
    /// Anything else; such operations are not implemented, so only keys that may write get
    /// as far as that answer.
    Other,
}

/// The class of the s3s operation `name`.
pub(crate) fn classify(name: &str) -> Class {
    match name {
        "ListBuckets" => Class::Service,
        "CreateBucket" => Class::CreateBucket,
        "DeleteBucket" | "PutBucketAcl" | "PutBucketPolicy" | "DeleteBucketPolicy" => {
            Class::BucketAdmin
        }
        "HeadBucket" => Class::HeadBucket,
        "PutBucketCors"
        | "DeleteBucketCors"
        | "PutBucketTagging"
        | "DeleteBucketTagging"
        | "PutBucketLifecycleConfiguration"
        | "DeleteBucketLifecycle"
        | "PutBucketWebsite"
        | "DeleteBucketWebsite" => Class::BucketConfig,
        "GetBucketLocation"
        | "GetBucketVersioning"
        | "GetBucketAcl"
        | "GetBucketCors"
        | "GetBucketPolicy"
        | "GetBucketPolicyStatus"
        | "GetBucketTagging"
        | "GetBucketLifecycleConfiguration"
        | "GetBucketWebsite"
        | "ListMultipartUploads" => Class::BucketRead,
        "ListObjects" | "ListObjectsV2" | "ListObjectVersions" => Class::List,
        "GetObject" | "HeadObject" | "GetObjectAttributes" => Class::ObjectRead,
        "GetObjectAcl" | "GetObjectTagging" => Class::ObjectAclRead,
        "PutObject"
        | "PostObject"
        | "CopyObject"
        | "DeleteObject"
        | "DeleteObjects"
        | "PutObjectAcl"
        | "PutObjectTagging"
        | "DeleteObjectTagging"
        | "CreateMultipartUpload"
        | "UploadPart"
        | "UploadPartCopy"
        | "CompleteMultipartUpload"
        | "AbortMultipartUpload"
        | "ListParts" => Class::ObjectWrite,
        _ => Class::Other,
    }
}

/// Who a request acts as.
#[derive(Debug, Clone)]
pub(crate) enum Caller {
    /// A request signed with this key.
    Key(Arc<SigningKey>),
    /// An unsigned request.
    Anonymous,
}

impl Caller {
    pub(crate) fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

/// What anonymous requests may do in a bucket right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Public {
    /// What they may read; `Private` while anonymous access is off server-wide or the owner's
    /// account is disabled.
    pub(crate) read: Anonymous,
    /// Whether they may list the bucket.
    pub(crate) list: bool,
}

impl Public {
    /// The effective anonymous access of `bucket`.
    pub(crate) fn of(bucket: &Bucket, allow_anonymous: bool) -> Self {
        if !allow_anonymous || !bucket.owner_enabled || bucket.anonymous == Anonymous::Private {
            return Self {
                read: Anonymous::Private,
                list: false,
            };
        }
        Self {
            read: bucket.anonymous,
            list: bucket.anonymous_list,
        }
    }
}

/// The outcome of the access check, handed to the operation.
#[derive(Debug, Clone)]
pub(crate) struct Authorized {
    pub(crate) caller: Caller,
    /// The bucket the request names, if it exists.
    pub(crate) bucket: Option<Arc<Bucket>>,
    /// The key's permission on that bucket (`None` for anonymous requests).
    pub(crate) permission: Option<Permission>,
}

impl Authorized {
    /// The bucket the request names; the access check made sure it exists.
    pub(crate) fn bucket(&self) -> S3Result<&Arc<Bucket>> {
        self.bucket.as_ref().ok_or_else(|| s3_error!(NoSuchBucket))
    }

    /// The anonymous access of the request's bucket.
    pub(crate) fn public(&self, allow_anonymous: bool) -> Public {
        self.bucket.as_deref().map_or(
            Public {
                read: Anonymous::Private,
                list: false,
            },
            |bucket| Public::of(bucket, allow_anonymous),
        )
    }

    /// An identity of the bucket owner whose mounts are `buckets`, each at its name, writable
    /// where the flag says so.
    pub(crate) fn identity(&self, buckets: &[(&Bucket, bool)]) -> S3Result<Arc<Identity>> {
        let first = buckets.first().ok_or_else(|| s3_error!(NoSuchBucket))?.0;
        let mut mounts = Vec::with_capacity(buckets.len());
        for (bucket, writable) in buckets {
            mounts.push(Mount {
                mount_path: RelPath::parse(&bucket.name)
                    .map_err(|_| s3_error!(InternalError, "bucket name is not a path"))?,
                storage_path: bucket.folder.clone(),
                writable: *writable,
            });
        }
        mounts.sort_by(|a, b| a.mount_path.cmp(&b.mount_path));
        mounts.dedup_by(|a, b| a.mount_path == b.mount_path);
        Ok(Arc::new(Identity {
            user_id: first.owner_id,
            username: first.owner_name.clone(),
            display_name: first.owner_display_name.clone(),
            app_password_id: match &self.caller {
                Caller::Key(key) => Some(key.id),
                Caller::Anonymous => None,
            },
            mounts,
            // Only requests the S3 service allows get this far.
            services: gono_server_core::services::Services::NONE
                .with(gono_server_core::services::Service::S3, true),
        }))
    }
}

/// The permission `key` has on `bucket`, if any.
pub(crate) fn permission(key: &SigningKey, bucket: &Bucket) -> Option<Permission> {
    if bucket.owner_id != key.user_id {
        return None;
    }
    key.grants
        .iter()
        .find(|grant| grant.bucket_id.is_none_or(|id| id == bucket.id))
        .map(|grant| grant.permission)
}

/// Whether `key` has a `full` grant on every bucket of its account.
pub(crate) fn may_administer(key: &SigningKey) -> bool {
    key.grants
        .iter()
        .any(|grant| grant.bucket_id.is_none() && grant.permission == Permission::Full)
}

/// Applies the access rules (see the module documentation). Returns the key's permission on
/// the bucket.
pub(crate) fn decide(
    caller: &Caller,
    bucket: Option<&Bucket>,
    class: Class,
    allow_anonymous: bool,
) -> Result<Option<Permission>, S3Error> {
    let key = match caller {
        Caller::Key(key) => key,
        Caller::Anonymous => {
            let public = bucket.map(|bucket| Public::of(bucket, allow_anonymous));
            let allowed = match (class, public) {
                (Class::List | Class::HeadBucket, Some(public)) => public.list,
                (Class::ObjectRead, Some(public)) => public.read != Anonymous::Private,
                _ => false,
            };
            return if allowed {
                Ok(None)
            } else {
                Err(s3_error!(AccessDenied))
            };
        }
    };
    match class {
        Class::Service => return Ok(None),
        Class::CreateBucket => {
            return if may_administer(key) {
                Ok(None)
            } else {
                Err(s3_error!(
                    AccessDenied,
                    "Creating buckets needs a key with full access to every bucket"
                ))
            };
        }
        _ => {}
    }
    let Some(bucket) = bucket else {
        return Err(s3_error!(NoSuchBucket));
    };
    let Some(permission) = permission(key, bucket) else {
        return Err(s3_error!(AccessDenied));
    };
    let allowed = match class {
        Class::BucketAdmin => may_administer(key),
        Class::ObjectWrite | Class::BucketConfig | Class::Other => permission == Permission::Full,
        _ => true,
    };
    if allowed {
        Ok(Some(permission))
    } else {
        Err(s3_error!(AccessDenied))
    }
}

/// The [`S3Access`] of the API.
pub(crate) struct Access {
    state: S3State,
}

impl Access {
    pub(crate) fn new(state: S3State) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl S3Access for Access {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let unavailable = |err: gono_server_core::Error| {
            tracing::error!(error = %err, "cannot check S3 access");
            s3_error!(ServiceUnavailable, "Please try again later")
        };
        let caller = match cx.credentials() {
            // The signature was checked with this key a moment ago; it is loaded again for
            // its grants.
            Some(credentials) => {
                let key = s3::signing_key(
                    self.state.pool(),
                    self.state.sealing(),
                    &credentials.access_key,
                    db::unix_now(),
                )
                .await
                .map_err(unavailable)?
                .ok_or_else(|| s3_error!(InvalidAccessKeyId))?;
                if !key.service {
                    return Err(s3_error!(
                        AccessDenied,
                        "S3 is not enabled for this account"
                    ));
                }
                Caller::Key(Arc::new(key))
            }
            None => Caller::Anonymous,
        };
        let bucket = match cx.s3_path().get_bucket_name() {
            Some(name) => s3::bucket(self.state.pool(), name)
                .await
                .map_err(unavailable)?
                .map(Arc::new),
            None => None,
        };
        let class = classify(cx.s3_op().name());
        let permission = decide(
            &caller,
            bucket.as_deref(),
            class,
            self.state.settings().allow_anonymous,
        )?;
        cx.extensions_mut().insert(Authorized {
            caller,
            bucket,
            permission,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gono_server_core::{Username, s3::Grant};
    use s3s::S3ErrorCode;
    use secrecy::SecretString;

    use super::*;

    fn bucket(id: i64, owner: i64, anonymous: Anonymous, list: bool) -> Bucket {
        Bucket {
            id,
            name: format!("bucket-{id}"),
            owner_id: owner,
            owner_name: Username::new("alice").unwrap(),
            owner_display_name: "Alice".into(),
            owner_enabled: true,
            root_file_id: 100 + id,
            folder: RelPath::parse(&format!("B{id}")).unwrap(),
            anonymous,
            anonymous_list: list,
            cors: None,
            tags: None,
            lifecycle: None,
            website: None,
            created_at: 0,
        }
    }

    fn key(user: i64, grants: Vec<Grant>) -> Caller {
        Caller::Key(Arc::new(SigningKey {
            id: 1,
            access_key_id: "GONOAAAAAAAAAAAAAAAA".into(),
            user_id: user,
            username: Username::new("alice").unwrap(),
            display_name: "Alice".into(),
            secret: SecretString::from("x"),
            grants,
            last_used_at: None,
            service: true,
        }))
    }

    fn code(result: Result<Option<Permission>, S3Error>) -> Option<S3ErrorCode> {
        result.err().map(|err| err.code().clone())
    }

    #[test]
    fn operations_are_classified() {
        assert_eq!(classify("GetObject"), Class::ObjectRead);
        assert_eq!(classify("ListObjectsV2"), Class::List);
        assert_eq!(classify("ListObjectVersions"), Class::List);
        assert_eq!(classify("CompleteMultipartUpload"), Class::ObjectWrite);
        assert_eq!(classify("PutBucketAcl"), Class::BucketAdmin);
        assert_eq!(classify("PutBucketCors"), Class::BucketConfig);
        assert_eq!(classify("GetBucketCors"), Class::BucketRead);
        assert_eq!(classify("PostObject"), Class::ObjectWrite);
        assert_eq!(classify("PutBucketPolicy"), Class::BucketAdmin);
        assert_eq!(classify("GetBucketPolicy"), Class::BucketRead);
        assert_eq!(classify("PutBucketTagging"), Class::BucketConfig);
        assert_eq!(classify("GetObjectTagging"), Class::ObjectAclRead);
        assert_eq!(classify("PutObjectTagging"), Class::ObjectWrite);
        assert_eq!(classify("PutBucketLogging"), Class::Other);
    }

    #[test]
    fn keys_act_within_their_grants() {
        let own = bucket(1, 7, Anonymous::Private, false);
        let other = bucket(2, 7, Anonymous::Private, false);
        let foreign = bucket(3, 8, Anonymous::PublicRead, true);
        let everything = key(7, vec![Grant::everything()]);
        let reader = key(
            7,
            vec![Grant {
                bucket_id: Some(1),
                permission: Permission::View,
            }],
        );
        let writer = key(
            7,
            vec![Grant {
                bucket_id: Some(1),
                permission: Permission::Full,
            }],
        );

        for class in [
            Class::Service,
            Class::CreateBucket,
            Class::BucketAdmin,
            Class::List,
            Class::ObjectWrite,
        ] {
            assert!(
                decide(&everything, Some(&own), class, false).is_ok(),
                "{class:?}"
            );
        }
        assert_eq!(
            decide(&reader, Some(&own), Class::ObjectRead, false).unwrap(),
            Some(Permission::View)
        );
        assert_eq!(
            code(decide(&reader, Some(&own), Class::ObjectWrite, false)),
            Some(S3ErrorCode::AccessDenied)
        );
        assert!(decide(&writer, Some(&own), Class::ObjectWrite, false).is_ok());
        assert!(
            decide(&writer, Some(&own), Class::BucketConfig, false).is_ok(),
            "CORS rules need a full grant on the bucket only"
        );
        assert_eq!(
            code(decide(&reader, Some(&own), Class::BucketConfig, false)),
            Some(S3ErrorCode::AccessDenied)
        );
        for caller in [&reader, &writer] {
            for class in [Class::CreateBucket, Class::BucketAdmin] {
                assert_eq!(
                    code(decide(caller, Some(&own), class, false)),
                    Some(S3ErrorCode::AccessDenied),
                    "{class:?}"
                );
            }
            assert_eq!(
                code(decide(caller, Some(&other), Class::ObjectRead, false)),
                Some(S3ErrorCode::AccessDenied),
                "a bucket without a grant"
            );
        }
        assert_eq!(
            code(decide(&everything, Some(&foreign), Class::ObjectRead, true)),
            Some(S3ErrorCode::AccessDenied),
            "another account's bucket, public or not"
        );
        assert_eq!(
            code(decide(&everything, None, Class::List, false)),
            Some(S3ErrorCode::NoSuchBucket)
        );
    }

    #[test]
    fn anonymous_requests_read_only_what_is_published() {
        let private = bucket(1, 7, Anonymous::Private, true);
        let acl = bucket(2, 7, Anonymous::Acl, false);
        let public = bucket(3, 7, Anonymous::PublicRead, true);
        let anonymous = Caller::Anonymous;
        let allowed = |bucket: Option<&Bucket>, class, allow| {
            decide(&anonymous, bucket, class, allow).is_ok()
        };

        assert!(allowed(Some(&public), Class::ObjectRead, true));
        assert!(allowed(Some(&public), Class::List, true));
        assert!(allowed(Some(&public), Class::HeadBucket, true));
        assert!(allowed(Some(&acl), Class::ObjectRead, true));
        assert!(!allowed(Some(&acl), Class::List, true), "listing is off");
        assert!(!allowed(Some(&private), Class::ObjectRead, true));
        assert!(
            !allowed(Some(&private), Class::List, true),
            "a private bucket lists nothing"
        );
        for class in [
            Class::ObjectWrite,
            Class::BucketConfig,
            Class::ObjectAclRead,
            Class::BucketRead,
            Class::BucketAdmin,
            Class::Service,
            Class::CreateBucket,
            Class::Other,
        ] {
            assert!(!allowed(Some(&public), class, true), "{class:?}");
        }
        // Off server-wide, missing, or the owner disabled: everything is private.
        assert!(!allowed(Some(&public), Class::ObjectRead, false));
        assert_eq!(
            code(decide(&anonymous, None, Class::ObjectRead, true)),
            Some(S3ErrorCode::AccessDenied)
        );
        let mut disabled = public.clone();
        disabled.owner_enabled = false;
        assert!(!allowed(Some(&disabled), Class::ObjectRead, true));
    }
}
