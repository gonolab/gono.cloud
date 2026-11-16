//! Bucket policies: only the anonymous-download policy, mapped onto the bucket's anonymous mode.
//!
//! `mc anonymous set download` (and other tools that publish a bucket the MinIO way) write a
//! policy that lets everyone (`"Principal": {"AWS": ["*"]}`) read every object
//! (`s3:GetObject` on `arn:aws:s3:::<bucket>/*`) and, usually, list the bucket
//! (`s3:ListBucket`, `s3:GetBucketLocation` on `arn:aws:s3:::<bucket>`). Such a policy sets the
//! bucket's mode to `public-read`, with anonymous listing if it allows `s3:ListBucket`.
//! Deleting the policy makes the bucket private.
//!
//! Every other policy is refused with `NotImplemented` and changes nothing: policies that let
//! anyone write (`mc anonymous set upload` or `public`), that name principals, prefixes or
//! conditions, or that deny. Gono Cloud stores no policy documents; `GetBucketPolicy` answers
//! with the policy that matches the bucket's effective anonymous access.

use s3s::{S3Error, S3ErrorCode, S3Result, s3_error};
use serde_json::{Value, json};

use crate::access::Public;
use gono_server_core::s3::Anonymous;

/// Largest policy accepted, as in S3.
const MAX_POLICY_BYTES: usize = 20 * 1024;

/// What an accepted policy allows anonymous requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Download {
    /// `s3:ListBucket`: anonymous listing.
    pub(crate) list: bool,
}

fn malformed(message: impl Into<String>) -> S3Error {
    S3Error::with_message(S3ErrorCode::MalformedPolicy, message.into())
}

fn unsupported() -> S3Error {
    s3_error!(
        NotImplemented,
        "Only the anonymous download policy is supported: s3:GetObject on every object for \
         everyone, optionally with s3:ListBucket and s3:GetBucketLocation on the bucket"
    )
}

/// The strings of a value that is a string or an array of strings.
fn strings(value: &Value) -> Option<Vec<&str>> {
    match value {
        Value::String(one) => Some(vec![one.as_str()]),
        Value::Array(many) => many.iter().map(Value::as_str).collect(),
        _ => None,
    }
}

/// Whether `principal` is everyone: `"*"`, `{"AWS": "*"}` or `{"AWS": ["*"]}`.
fn is_everyone(principal: &Value) -> bool {
    match principal {
        Value::String(any) => any == "*",
        Value::Object(map) => {
            map.len() == 1
                && map
                    .get("AWS")
                    .and_then(strings)
                    .is_some_and(|aws| aws == ["*"])
        }
        _ => false,
    }
}

/// Checks `policy` for the bucket `bucket`.
pub(crate) fn parse(bucket: &str, policy: &str) -> S3Result<Download> {
    if policy.len() > MAX_POLICY_BYTES {
        return Err(malformed("Policies are at most 20 KB"));
    }
    let document: Value =
        serde_json::from_str(policy).map_err(|err| malformed(format!("Invalid JSON: {err}")))?;
    let statements = match document.get("Statement") {
        Some(Value::Array(statements)) => statements.iter().collect::<Vec<_>>(),
        Some(statement @ Value::Object(_)) => vec![statement],
        _ => return Err(malformed("The policy has no Statement")),
    };
    if statements.is_empty() {
        return Err(malformed("The policy has no Statement"));
    }
    let bucket_arn = format!("arn:aws:s3:::{bucket}");
    let objects_arn = format!("{bucket_arn}/*");
    let mut objects = false;
    let mut list = false;
    for statement in statements {
        let Value::Object(fields) = statement else {
            return Err(malformed("A statement is not an object"));
        };
        if fields.keys().any(|name| {
            !matches!(
                name.as_str(),
                "Sid" | "Effect" | "Principal" | "Action" | "Resource"
            )
        }) {
            // Condition, NotAction, NotResource, NotPrincipal.
            return Err(unsupported());
        }
        if fields.get("Effect").and_then(Value::as_str) != Some("Allow") {
            return Err(unsupported());
        }
        if !fields.get("Principal").is_some_and(is_everyone) {
            return Err(unsupported());
        }
        let actions = fields
            .get("Action")
            .and_then(strings)
            .ok_or_else(|| malformed("A statement has no Action"))?;
        let resources = fields
            .get("Resource")
            .and_then(strings)
            .ok_or_else(|| malformed("A statement has no Resource"))?;
        for resource in &resources {
            if *resource != bucket_arn && *resource != objects_arn {
                if resource.starts_with(&format!("{bucket_arn}/")) {
                    // A prefix of the bucket.
                    return Err(unsupported());
                }
                return Err(malformed(format!(
                    "Policy has invalid resource {resource}: it must be {bucket_arn} or \
                     {objects_arn}"
                )));
            }
        }
        for action in actions {
            let on = |arn: &str| resources.contains(&arn);
            match action.to_ascii_lowercase().as_str() {
                "s3:getobject" if on(&objects_arn) => objects = true,
                "s3:listbucket" if on(&bucket_arn) => list = true,
                "s3:getbucketlocation" if on(&bucket_arn) => {}
                "s3:getobject" | "s3:listbucket" | "s3:getbucketlocation" => {
                    return Err(malformed(format!(
                        "Action {action} does not apply to the statement's resources"
                    )));
                }
                // Writes (s3:PutObject, s3:DeleteObject, s3:*, ...) and everything else.
                _ => return Err(unsupported()),
            }
        }
    }
    if !objects {
        return Err(unsupported());
    }
    Ok(Download { list })
}

/// The policy that matches `public`, the effective anonymous access of `bucket`; `None` when
/// anonymous requests may read and list nothing (or only objects with a public ACL).
pub(crate) fn document(bucket: &str, public: Public) -> Option<String> {
    let bucket_arn = format!("arn:aws:s3:::{bucket}");
    let everyone = json!({ "AWS": ["*"] });
    let mut statements = Vec::new();
    if public.list {
        statements.push(json!({
            "Effect": "Allow",
            "Principal": everyone,
            "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [bucket_arn],
        }));
    }
    if public.read == Anonymous::PublicRead {
        statements.push(json!({
            "Effect": "Allow",
            "Principal": everyone,
            "Action": ["s3:GetObject"],
            "Resource": [format!("{bucket_arn}/*")],
        }));
    }
    (!statements.is_empty())
        .then(|| json!({ "Version": "2012-10-17", "Statement": statements }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy `mc anonymous set download` writes.
    const MC_DOWNLOAD: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::photos"]},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::photos/*"]}]}"#;

    /// The policy `mc anonymous set upload` writes.
    const MC_UPLOAD: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetBucketLocation","s3:ListBucketMultipartUploads"],"Resource":["arn:aws:s3:::photos"]},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:AbortMultipartUpload","s3:DeleteObject","s3:ListMultipartUploadParts","s3:PutObject"],"Resource":["arn:aws:s3:::photos/*"]}]}"#;

    fn code(result: S3Result<Download>) -> S3ErrorCode {
        result.unwrap_err().code().clone()
    }

    #[test]
    fn the_download_policy_publishes_the_bucket() {
        assert_eq!(
            parse("photos", MC_DOWNLOAD).unwrap(),
            Download { list: true }
        );
        let objects_only = r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}}"#;
        assert_eq!(
            parse("photos", objects_only).unwrap(),
            Download { list: false }
        );
    }

    #[test]
    fn other_policies_are_not_implemented() {
        assert_eq!(
            code(parse("photos", MC_UPLOAD)),
            S3ErrorCode::NotImplemented
        );
        let public = MC_DOWNLOAD.replace("\"s3:GetObject\"", "\"s3:GetObject\",\"s3:PutObject\"");
        assert_eq!(code(parse("photos", &public)), S3ErrorCode::NotImplemented);
        let star = MC_DOWNLOAD.replace("\"s3:GetObject\"", "\"s3:*\"");
        assert_eq!(code(parse("photos", &star)), S3ErrorCode::NotImplemented);
        let prefix = MC_DOWNLOAD.replace("photos/*", "photos/public/*");
        assert_eq!(code(parse("photos", &prefix)), S3ErrorCode::NotImplemented);
        let deny = MC_DOWNLOAD.replace("Allow", "Deny");
        assert_eq!(code(parse("photos", &deny)), S3ErrorCode::NotImplemented);
        let someone = MC_DOWNLOAD.replace("[\"*\"]", "[\"arn:aws:iam::1:root\"]");
        assert_eq!(code(parse("photos", &someone)), S3ErrorCode::NotImplemented);
        let condition = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#;
        assert_eq!(
            code(parse("photos", condition)),
            S3ErrorCode::NotImplemented
        );
        let list_only = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::photos"}]}"#;
        assert_eq!(
            code(parse("photos", list_only)),
            S3ErrorCode::NotImplemented
        );
    }

    #[test]
    fn malformed_policies_are_refused() {
        for policy in [
            "not json",
            "{}",
            r#"{"Statement":[]}"#,
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Resource":"arn:aws:s3:::photos/*"}]}"#,
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}"#,
            // Another bucket, or the action on the wrong resource.
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}]}"#,
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos"}]}"#,
        ] {
            assert_eq!(
                code(parse("photos", policy)),
                S3ErrorCode::MalformedPolicy,
                "{policy}"
            );
        }
        let large = format!("{{\"Sid\":\"{}\"}}", "x".repeat(MAX_POLICY_BYTES));
        assert_eq!(code(parse("photos", &large)), S3ErrorCode::MalformedPolicy);
    }

    #[test]
    fn documents_describe_the_effective_access() {
        let public = |read, list| Public { read, list };
        let document_of = |read, list| document("photos", public(read, list));
        let full = document_of(Anonymous::PublicRead, true).unwrap();
        assert_eq!(parse("photos", &full).unwrap(), Download { list: true });
        let read = document_of(Anonymous::PublicRead, false).unwrap();
        assert_eq!(parse("photos", &read).unwrap(), Download { list: false });
        assert!(!read.contains("ListBucket"));
        assert_eq!(document_of(Anonymous::Private, false), None);
        assert_eq!(document_of(Anonymous::Acl, false), None);
        let list = document_of(Anonymous::Acl, true).unwrap();
        assert!(list.contains("s3:ListBucket") && !list.contains("s3:GetObject"));
    }
}
