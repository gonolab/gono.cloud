//! Browser form uploads (`POST` with `multipart/form-data`): the fields s3s does not read.
//!
//! s3s takes a form's canned ACL only from a field `x-amz-acl`, while S3 and the tools that
//! build forms (for example boto3's `generate_presigned_post`) name it `acl`. The fields of a
//! form come before its file, so the server reads ahead until the file begins (at most
//! [`READ_AHEAD`] bytes), takes the `acl` field, and hands the body on unchanged. s3s then checks
//! every field of the signed form, `acl` included, against the policy: the value read here is the
//! one the policy allows. A form that names `acl` twice is refused, so that the value read here
//! and the value s3s checks cannot differ.

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt as _;
use http::{HeaderMap, header};
use http_body::Frame;
use http_body_util::{BodyExt, BodyStream, StreamBody};

/// Most bytes of a form read ahead for its fields.
const READ_AHEAD: usize = 1024 * 1024;

/// The `acl` field of a form upload, for the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormAcl {
    /// The form names this canned ACL.
    Named(String),
    /// The form names an ACL more than once.
    Repeated,
}

/// The boundary of a `multipart/form-data` body, from its `Content-Type`.
pub(crate) fn boundary(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let (kind, parameters) = value.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    parameters.split(';').find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|boundary| !boundary.is_empty())
    })
}

/// Positions of `needle` in `haystack`.
fn positions(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    (0..=haystack.len() - needle.len())
        .filter(|&at| &haystack[at..at + needle.len()] == needle)
        .collect()
}

/// The name of a part and whether it is a file, from its headers.
fn part_name(headers: &[u8]) -> Option<(String, bool)> {
    let headers = std::str::from_utf8(headers).ok()?;
    let disposition = headers.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-disposition")
            .then_some(value)
    })?;
    let mut name = None;
    let mut file = false;
    for parameter in disposition.split(';').skip(1) {
        let Some((key, value)) = parameter.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim().to_ascii_lowercase().as_str() {
            "name" => name = Some(value.to_owned()),
            "filename" => file = true,
            _ => {}
        }
    }
    let name = name?;
    let file = file || name.eq_ignore_ascii_case("file");
    Some((name, file))
}

/// The complete fields at the start of a form body: each part between two delimiters, up to
/// the file. Returns the fields and whether the file (or the end of the form) was reached.
fn fields(buffer: &[u8], boundary: &str) -> (Vec<(String, Vec<u8>)>, bool) {
    let delimiter = format!("--{boundary}");
    let starts = positions(buffer, delimiter.as_bytes());
    let mut fields = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let part_start = start + delimiter.len();
        if buffer[part_start..].starts_with(b"--") {
            // The closing delimiter: the form is complete.
            return (fields, true);
        }
        let part_end = starts.get(index + 1).copied();
        let tail = &buffer[part_start..part_end.unwrap_or(buffer.len())];
        let tail = tail.strip_prefix(b"\r\n").unwrap_or(tail);
        let Some(split) = positions(tail, b"\r\n\r\n").first().copied() else {
            return (fields, false);
        };
        let Some((name, file)) = part_name(&tail[..split]) else {
            continue;
        };
        if file {
            return (fields, true);
        }
        // A field is complete once the next delimiter has arrived.
        if part_end.is_none() {
            return (fields, false);
        }
        let value = &tail[split + 4..];
        let value = value.strip_suffix(b"\r\n").unwrap_or(value);
        fields.push((name, value.to_vec()));
    }
    (fields, false)
}

/// The `acl` of `fields`, if any.
fn acl_of(fields: &[(String, Vec<u8>)]) -> Option<FormAcl> {
    let mut named = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("acl"));
    let first = named.next()?;
    if named.next().is_some() {
        return Some(FormAcl::Repeated);
    }
    Some(FormAcl::Named(
        String::from_utf8_lossy(&first.1).into_owned(),
    ))
}

/// Reads the fields of the form `body` (with `boundary`) ahead, and returns the `acl` field
/// and the whole body again.
pub(crate) async fn read_acl<B>(
    body: B,
    boundary: String,
) -> (
    Option<FormAcl>,
    StreamBody<impl futures_util::Stream<Item = Result<Frame<Bytes>, B::Error>> + Send>,
)
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Send,
{
    let mut body = Box::pin(body);
    let mut read: Vec<Frame<Bytes>> = Vec::new();
    let mut buffer = BytesMut::new();
    let mut failed = None;
    let acl = loop {
        let (found, done) = fields(&buffer, &boundary);
        if done || buffer.len() > READ_AHEAD {
            break acl_of(&found);
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    buffer.extend_from_slice(data);
                }
                read.push(frame);
            }
            Some(Err(err)) => {
                failed = Some(err);
                break None;
            }
            None => break acl_of(&fields(&buffer, &boundary).0),
        }
    };
    let replay = futures_util::stream::iter(read.into_iter().map(Ok).chain(failed.map(Err)));
    (acl, StreamBody::new(replay.chain(BodyStream::new(body))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(fields: &[(&str, &str)], boundary: &str) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
                 filename=\"a.txt\"\r\n\r\ncontent\r\n--{boundary}--\r\n"
            )
            .as_bytes(),
        );
        body
    }

    #[test]
    fn boundaries_come_from_the_content_type() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=\"abc def\"".parse().unwrap(),
        );
        assert_eq!(boundary(&headers).as_deref(), Some("abc def"));
        headers.insert(
            header::CONTENT_TYPE,
            "Multipart/Form-Data;charset=utf-8; Boundary=xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(boundary(&headers).as_deref(), Some("xyz"));
        headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(boundary(&headers), None);
    }

    #[test]
    fn fields_before_the_file_are_read() {
        let body = form(&[("key", "a/${filename}"), ("acl", "public-read")], "b0");
        let (found, done) = fields(&body, "b0");
        assert!(done);
        assert_eq!(found.len(), 2);
        assert_eq!(acl_of(&found), Some(FormAcl::Named("public-read".into())));
        // A field is taken only once it is complete.
        let cut = body.len() - 120;
        let (found, done) = fields(&body[..30], "b0");
        assert!(!done && found.is_empty());
        assert!(fields(&body[..cut], "b0").0.len() <= 2);
        let twice = form(&[("acl", "private"), ("ACL", "public-read")], "b0");
        assert_eq!(acl_of(&fields(&twice, "b0").0), Some(FormAcl::Repeated));
        assert_eq!(acl_of(&fields(&form(&[("key", "k")], "b0"), "b0").0), None);
    }

    #[tokio::test]
    async fn the_body_is_handed_on_unchanged() {
        let body = form(&[("acl", "public-read"), ("key", "k")], "xyz");
        let chunks: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = body
            .chunks(7)
            .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
            .collect();
        let source = StreamBody::new(futures_util::stream::iter(chunks));
        let (acl, replayed) = read_acl(source, "xyz".to_owned()).await;
        assert_eq!(acl, Some(FormAcl::Named("public-read".into())));
        let collected = BodyExt::collect(replayed).await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from(body));
    }
}
