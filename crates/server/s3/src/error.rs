//! S3 errors for what the tree and the database report.

use gono_server_dav::ObjectError;
use http::StatusCode;
use s3s::{S3Error, S3ErrorCode, s3_error};

use crate::keys::KeyError;

/// A key that the tree cannot hold next to what is there: it names a folder, or lies below a
/// file. S3 itself has no such conflict, so the error has a code of its own and `409`, which
/// clients do not retry.
pub(crate) fn conflict(message: &'static str) -> S3Error {
    let mut err = S3Error::with_message(S3ErrorCode::Custom("KeyConflict".into()), message);
    err.set_status_code(StatusCode::CONFLICT);
    err
}

/// The error of an object operation. `anonymous` requests get `AccessDenied` for missing
/// objects too.
pub(crate) fn object(err: ObjectError, anonymous: bool) -> S3Error {
    match err {
        ObjectError::NotFound if anonymous => s3_error!(AccessDenied),
        ObjectError::NotFound => s3_error!(NoSuchKey),
        ObjectError::Forbidden => s3_error!(AccessDenied),
        ObjectError::IsFolder => conflict("The key names a folder"),
        ObjectError::ParentIsFile => {
            conflict("A parent of the key is an object, so nothing can be stored below it")
        }
        ObjectError::PreconditionFailed => s3_error!(PreconditionFailed),
        ObjectError::InsufficientStorage => {
            s3_error!(ServiceUnavailable, "The server is out of storage")
        }
        ObjectError::Failed => s3_error!(InternalError),
    }
}

/// The error of a key that cannot be stored.
pub(crate) fn key(err: &KeyError) -> S3Error {
    match err {
        KeyError::TooLong => s3_error!(KeyTooLongError),
        KeyError::Invalid(reason) => S3Error::with_message(S3ErrorCode::InvalidArgument, *reason),
    }
}

/// Logs a database failure and answers `ServiceUnavailable`, which clients retry.
pub(crate) fn database(err: gono_server_core::Error) -> S3Error {
    tracing::error!(error = %err, "S3 request failed in the database");
    s3_error!(ServiceUnavailable, "Please try again later")
}

/// Logs an I/O failure and answers `InternalError`.
pub(crate) fn io(err: std::io::Error) -> S3Error {
    tracing::error!(error = %err, "S3 request failed on disk");
    match err.kind() {
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            s3_error!(ServiceUnavailable, "The server is out of storage")
        }
        _ => s3_error!(InternalError),
    }
}
