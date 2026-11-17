//! Browser form uploads (`POST` with `multipart/form-data`): the fields s3s does not read.
//!
//! s3s takes a form's canned ACL only from a field `x-amz-acl`, while S3 and the tools that
//! build forms (for example boto3's `generate_presigned_post`) name it `acl`. The fields of a
//! form come before its file, so the server reads ahead until the file begins, takes the `acl`
//! field, and hands the body on unchanged. s3s then checks every field of the signed form, `acl`
//! included, against the policy.
//!
//! The value taken here must be the one s3s checks, or a form could carry an `acl` that its
//! policy never allowed. So the form is read exactly as s3s reads it:
//! - the same media type rules ([`media_type`]: one `Content-Type` header, parsed with `mime`);
//! - the same parser (`s3s-multipart`) with the same header limit ([`MAX_FIELD_SIZE`]);
//! - the same reading of a part: its last `Content-Disposition` header, that header's first
//!   `name`, and the file being the part named `file`.
//!
//! A form that names `acl` more than once is refused (s3s would check only one of the values),
//! and so is a form that the parser cannot read or whose fields do not end within
//! [`READ_AHEAD`] bytes: the upload never goes on with an `acl` that was not found the way s3s
//! finds it.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use http::{HeaderMap, header};
use http_body::Frame;
use http_body_util::{BodyStream, StreamBody};
use s3s_multipart::{Boundary, Multipart, parse_content_disposition};

/// Most bytes of a form read ahead for its fields: a form whose file starts later is refused.
const READ_AHEAD: usize = 1024 * 1024;

/// Most bytes of a part's header block and of a field, here and in s3s
/// (`form_max_field_size`, set from this in `crate::service`), so that both parsers read the
/// same forms.
pub(crate) const MAX_FIELD_SIZE: usize = 1024 * 1024;

/// The `acl` field of a form upload, for the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormAcl {
    /// The form names this canned ACL.
    Named(String),
    /// The form names an ACL more than once.
    Repeated,
}

/// What reading a form ahead found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadAhead {
    /// The fields before the file were read: the form's `acl`, if it names one.
    Fields(Option<FormAcl>),
    /// The fields do not end within [`READ_AHEAD`] bytes.
    TooLarge,
    /// The form cannot be read (no file part, a part without a name, a malformed body).
    Malformed,
    /// The body failed; the failure is handed on to s3s with the body.
    Failed,
}

/// The media type of a request that s3s answers as a form upload when it is a `POST`: exactly
/// one `Content-Type` header, valid UTF-8 and not empty, that `mime` parses as
/// `multipart/form-data` (s3s's `extract_mime`). The boundary is its `boundary` parameter.
pub(crate) fn media_type(headers: &HeaderMap) -> Option<mime::Mime> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = std::str::from_utf8(value.as_bytes()).ok()?;
    if value.is_empty() {
        return None;
    }
    let media = value.parse::<mime::Mime>().ok()?;
    (media.type_() == mime::MULTIPART && media.subtype() == mime::FORM_DATA).then_some(media)
}

/// A field name, value or header parameter as s3s takes it: UTF-8 or a malformed form.
fn text(bytes: &[u8]) -> Result<String, ()> {
    std::str::from_utf8(bytes).map(str::to_owned).map_err(drop)
}

/// The `acl` of the form that `parser` reads: the fields up to the part named `file`, each
/// part read as s3s's `transform_multipart` reads it.
async fn acl_of<S>(parser: &mut Multipart<S>) -> Result<Option<FormAcl>, ()>
where
    S: Stream<Item = Result<Bytes, s3s_multipart::Error>> + Send + Unpin,
{
    let mut acl = None;
    loop {
        // A form that ends without a file is malformed for s3s too.
        let mut part = parser.next_part().await.map_err(drop)?.ok_or(())?;
        let mut name = None;
        while let Some(header) = part.next_header().await.map_err(drop)? {
            if header.name.eq_ignore_ascii_case("content-disposition") {
                // The last header wins, with the first `name` it carries (none when it has
                // none).
                name = parse_content_disposition(header.value)
                    .and_then(|disposition| disposition.name)
                    .map(text)
                    .transpose()?;
            }
        }
        let name = name.ok_or(())?;
        if name.eq_ignore_ascii_case("file") {
            return Ok(acl);
        }
        let mut value = Vec::new();
        while let Some(chunk) = part.next_data().await.map_err(drop)? {
            value.extend_from_slice(&chunk);
            if value.len() > MAX_FIELD_SIZE {
                return Err(());
            }
        }
        let value = text(&value)?;
        // s3s compares field names in lower case.
        if name.eq_ignore_ascii_case("acl") {
            acl = Some(match acl {
                None => FormAcl::Named(value),
                Some(_) => FormAcl::Repeated,
            });
        }
    }
}

/// The body of a form as the parser reads it: every frame is kept for the replay, and no more
/// than [`READ_AHEAD`] bytes are asked for.
struct Recording<'a, B: http_body::Body> {
    body: Pin<&'a mut B>,
    read: &'a mut Vec<Frame<Bytes>>,
    failed: &'a mut Option<B::Error>,
    too_large: &'a mut bool,
    bytes: usize,
}

impl<B> Stream for Recording<'_, B>
where
    B: http_body::Body<Data = Bytes>,
{
    type Item = Result<Bytes, s3s_multipart::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // The parser asks for more only while the file has not begun; a frame that
            // carries the start of the file as well is never cut.
            if this.bytes >= READ_AHEAD {
                *this.too_large = true;
                return Poll::Ready(Some(Err(s3s_multipart::Error::stream_read_failed(
                    "the fields of the form are too large",
                ))));
            }
            match ready!(this.body.as_mut().poll_frame(cx)) {
                None => return Poll::Ready(None),
                Some(Err(err)) => {
                    *this.failed = Some(err);
                    return Poll::Ready(Some(Err(s3s_multipart::Error::stream_read_failed(
                        "the body of the form failed",
                    ))));
                }
                Some(Ok(frame)) => {
                    let data = frame.data_ref().cloned();
                    this.read.push(frame);
                    if let Some(data) = data {
                        this.bytes += data.len();
                        return Poll::Ready(Some(Ok(data)));
                    }
                }
            }
        }
    }
}

/// Reads the fields of the form `body` (with `boundary`) ahead, and returns what they hold
/// and the whole body again.
pub(crate) async fn read_ahead<B>(
    body: B,
    boundary: &str,
) -> (
    ReadAhead,
    StreamBody<impl Stream<Item = Result<Frame<Bytes>, B::Error>> + Send + use<B>>,
)
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Send,
{
    let mut body = Box::pin(body);
    let mut read: Vec<Frame<Bytes>> = Vec::new();
    let mut failed = None;
    let mut too_large = false;
    let found = match Boundary::new(boundary.as_bytes()) {
        Err(_) => Err(()),
        Ok(boundary) => {
            let recording = Recording {
                body: body.as_mut(),
                read: &mut read,
                failed: &mut failed,
                too_large: &mut too_large,
                bytes: 0,
            };
            let mut parser = Multipart::new(recording, &boundary, MAX_FIELD_SIZE);
            acl_of(&mut parser).await
        }
    };
    let found = if failed.is_some() {
        ReadAhead::Failed
    } else if too_large {
        ReadAhead::TooLarge
    } else {
        match found {
            Ok(acl) => ReadAhead::Fields(acl),
            Err(()) => ReadAhead::Malformed,
        }
    };
    let replay = futures_util::stream::iter(read.into_iter().map(Ok).chain(failed.map(Err)));
    (found, StreamBody::new(replay.chain(BodyStream::new(body))))
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    const FILE: &str = "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n\
                        content";

    /// A form of `parts` (each its header lines and value, joined by an empty line) and a file,
    /// with the boundary `B`.
    fn raw(parts: &[&str]) -> Vec<u8> {
        let mut body = String::new();
        for part in parts.iter().chain([&FILE]) {
            body.push_str("--B\r\n");
            body.push_str(part);
            body.push_str("\r\n");
        }
        body.push_str("--B--\r\n");
        body.into_bytes()
    }

    /// A part of a plain field.
    fn field(name: &str, value: &str) -> String {
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}")
    }

    /// Reads `body` ahead in chunks of `chunk` bytes; checks that it is handed on unchanged.
    async fn read_chunked(body: &[u8], chunk: usize) -> ReadAhead {
        let chunks: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = body
            .chunks(chunk)
            .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
            .collect();
        let source = StreamBody::new(futures_util::stream::iter(chunks));
        let (found, replayed) = read_ahead(source, "B").await;
        let collected = BodyExt::collect(replayed).await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::copy_from_slice(body));
        found
    }

    async fn read(body: &[u8]) -> ReadAhead {
        let whole = read_chunked(body, body.len().max(1)).await;
        assert_eq!(read_chunked(body, 7).await, whole);
        whole
    }

    fn named(acl: &str) -> ReadAhead {
        ReadAhead::Fields(Some(FormAcl::Named(acl.to_owned())))
    }

    #[test]
    fn the_media_type_is_read_as_s3s_reads_it() {
        let boundary = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, value.parse().unwrap());
            media_type(&headers).and_then(|media| {
                media
                    .get_param(mime::BOUNDARY)
                    .map(|b| b.as_str().to_owned())
            })
        };
        assert_eq!(
            boundary("multipart/form-data; boundary=\"abc def\"").as_deref(),
            Some("abc def")
        );
        assert_eq!(
            boundary("Multipart/Form-Data;charset=utf-8; Boundary=xyz").as_deref(),
            Some("xyz")
        );
        assert_eq!(boundary("text/plain"), None);
        // Two Content-Type headers: s3s does not take the request as a form.
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=a".parse().unwrap(),
        );
        headers.append(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=b".parse().unwrap(),
        );
        assert!(media_type(&headers).is_none());
    }

    #[tokio::test]
    async fn the_acl_before_the_file_is_read() {
        let form = raw(&[&field("key", "a/${filename}"), &field("acl", "public-read")]);
        assert_eq!(read(&form).await, named("public-read"));
        assert_eq!(
            read(&raw(&[&field("key", "k")])).await,
            ReadAhead::Fields(None)
        );
        let twice = raw(&[&field("acl", "private"), &field("ACL", "public-read")]);
        assert_eq!(
            read(&twice).await,
            ReadAhead::Fields(Some(FormAcl::Repeated))
        );
        // No file part, or a part without a name: s3s refuses the form as well.
        assert_eq!(
            read(b"--B\r\n\r\nx\r\n--B--\r\n").await,
            ReadAhead::Malformed
        );
        let unnamed = raw(&["Content-Disposition: form-data\r\n\r\nx"]);
        assert_eq!(read(&unnamed).await, ReadAhead::Malformed);
    }

    // Forms that read differently with a parser of its own than with s3s's: the acl found
    // is always the one s3s checks against the policy (or the form is refused).

    #[tokio::test]
    async fn a_delimiter_inside_a_value_is_data() {
        let smuggled = field(
            "x-ignore-a",
            "x--B\r\nContent-Disposition: form-data; name=\"acl\"\r\n\r\npublic-read",
        );
        let form = raw(&[&smuggled, &field("acl", "private")]);
        assert_eq!(read(&form).await, named("private"));
    }

    #[tokio::test]
    async fn only_the_part_named_file_is_the_file() {
        let stopper =
            "Content-Disposition: form-data; name=\"x-ignore-z\"; filename=\"q\"\r\n\r\nq";
        let form = raw(&[stopper, &field("acl", "private")]);
        assert_eq!(read(&form).await, named("private"));
        let form = raw(&[
            &field("acl", "public-read"),
            stopper,
            &field("acl", "private"),
        ]);
        assert_eq!(
            read(&form).await,
            ReadAhead::Fields(Some(FormAcl::Repeated))
        );
    }

    #[tokio::test]
    async fn the_first_name_of_a_part_counts() {
        let smuggled =
            "Content-Disposition: form-data; name=\"x-ignore-a\"; name=\"acl\"\r\n\r\npublic-read";
        let hidden =
            "Content-Disposition: form-data; name=\"acl\"; name=\"x-ignore-b\"\r\n\r\nprivate";
        assert_eq!(read(&raw(&[smuggled, hidden])).await, named("private"));
        assert_eq!(read(&raw(&[smuggled])).await, ReadAhead::Fields(None));
        // A quoted `;` belongs to the name.
        let quoted =
            "Content-Disposition: form-data; name=\"x-ignore-a;name=acl\"\r\n\r\npublic-read";
        assert_eq!(read(&raw(&[quoted])).await, ReadAhead::Fields(None));
    }

    #[tokio::test]
    async fn the_last_content_disposition_of_a_part_counts() {
        let part = "Content-Disposition: form-data; name=\"acl\"\r\n\
                    Content-Disposition: form-data; name=\"x-ignore-a\"\r\n\r\npublic-read";
        assert_eq!(read(&raw(&[part])).await, ReadAhead::Fields(None));
    }

    #[tokio::test]
    async fn fields_beyond_the_read_ahead_are_refused() {
        let filler = "f".repeat(512 * 1024);
        let form = raw(&[
            &field("acl", "public-read"),
            &field("x-ignore-1", &filler),
            &field("x-ignore-2", &filler),
            &field("acl", "private"),
        ]);
        assert_eq!(read_chunked(&form, 16 * 1024).await, ReadAhead::TooLarge);
        // A body that arrives in one piece, file included, is read as a whole.
        let form = raw(&[&field("acl", "public-read"), &field("x-ignore-1", &filler)]);
        let mut whole = form.clone();
        whole.splice(
            whole.len() - 9..whole.len() - 9,
            "z".repeat(READ_AHEAD).bytes(),
        );
        assert_eq!(
            read_chunked(&whole, whole.len()).await,
            named("public-read")
        );
    }
}
