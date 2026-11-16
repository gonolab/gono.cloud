//! Checksums of multipart uploads.
//!
//! `CreateMultipartUpload` names an algorithm (`x-amz-checksum-algorithm`) and a type
//! (`x-amz-checksum-type`); every part then gets its checksum in that algorithm (computed by
//! the server whether or not the client sent one), and the completion derives the object's
//! checksum from the parts, as S3 does:
//!
//! - `COMPOSITE` (SHA-1, SHA-256, CRC32, CRC32C; the default except for CRC64NVME): the
//!   checksum of the parts' raw checksums one after another, in base64, followed by
//!   `-<parts>`.
//! - `FULL_OBJECT` (CRC32, CRC32C, CRC64NVME; the only type of CRC64NVME): the CRC of the whole
//!   content, combined from the parts' CRCs and sizes without reading the data again.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc_fast::CrcAlgorithm;
use s3s::{S3Result, checksum::ChecksumHasher, s3_error};

use crate::upload;

/// The checksum algorithm and type of a multipart upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UploadChecksum {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1` or `SHA256`.
    pub(crate) algorithm: &'static str,
    /// `COMPOSITE` rather than `FULL_OBJECT`.
    pub(crate) composite: bool,
}

impl UploadChecksum {
    /// The checksum `CreateMultipartUpload` asks for: `None` without an algorithm.
    pub(crate) fn requested(
        algorithm: Option<&str>,
        checksum_type: Option<&str>,
    ) -> S3Result<Option<Self>> {
        let Some(algorithm) = algorithm else {
            return match checksum_type {
                None => Ok(None),
                Some(_) => Err(s3_error!(
                    InvalidRequest,
                    "x-amz-checksum-type needs x-amz-checksum-algorithm"
                )),
            };
        };
        let algorithm = Self::algorithm(algorithm).ok_or_else(|| {
            s3_error!(
                InvalidRequest,
                "Multipart uploads support the checksum algorithms CRC32, CRC32C, CRC64NVME, \
                 SHA1 and SHA256"
            )
        })?;
        let full_object_only = algorithm == "CRC64NVME";
        let composite = match checksum_type.map(str::to_ascii_uppercase).as_deref() {
            None => !full_object_only,
            Some("COMPOSITE") => true,
            Some("FULL_OBJECT") => false,
            Some(_) => {
                return Err(s3_error!(
                    InvalidRequest,
                    "x-amz-checksum-type is COMPOSITE or FULL_OBJECT"
                ));
            }
        };
        if composite && full_object_only {
            return Err(s3_error!(
                InvalidRequest,
                "The checksum type COMPOSITE is not supported for CRC64NVME"
            ));
        }
        if !composite && matches!(algorithm, "SHA1" | "SHA256") {
            return Err(s3_error!(
                InvalidRequest,
                "The checksum type FULL_OBJECT is supported for CRC32, CRC32C and CRC64NVME"
            ));
        }
        Ok(Some(Self {
            algorithm,
            composite,
        }))
    }

    /// The checksum stored with an upload (as [`Self::algorithm`] and [`Self::type_name`]).
    pub(crate) fn stored(algorithm: &str, checksum_type: &str) -> Option<Self> {
        Some(Self {
            algorithm: Self::algorithm(algorithm)?,
            composite: checksum_type == "COMPOSITE",
        })
    }

    /// The algorithms a multipart upload may use, in their canonical spelling.
    fn algorithm(name: &str) -> Option<&'static str> {
        ["CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"]
            .into_iter()
            .find(|known| known.eq_ignore_ascii_case(name))
    }

    /// `COMPOSITE` or `FULL_OBJECT`.
    pub(crate) fn type_name(self) -> &'static str {
        if self.composite {
            "COMPOSITE"
        } else {
            "FULL_OBJECT"
        }
    }

    /// The object's checksum (base64, with `-<parts>` when composite) from its parts' sizes and
    /// checksums (base64, in this algorithm). `None` if a part has none or one is malformed.
    pub(crate) fn of_parts<'a>(
        self,
        parts: impl ExactSizeIterator<Item = (u64, Option<&'a str>)>,
    ) -> Option<String> {
        let count = parts.len();
        if self.composite {
            let mut hasher = ChecksumHasher::default();
            upload::enable(&mut hasher, self.algorithm);
            for (_, checksum) in parts {
                hasher.update(&STANDARD.decode(checksum?).ok()?);
            }
            let checksum = hasher.finalize();
            let value = upload::field(&checksum, self.algorithm).clone()?;
            return Some(format!("{value}-{count}"));
        }
        let (crc, width) = match self.algorithm {
            "CRC32" => (CrcAlgorithm::Crc32IsoHdlc, 4),
            "CRC32C" => (CrcAlgorithm::Crc32Iscsi, 4),
            _ => (CrcAlgorithm::Crc64Nvme, 8),
        };
        let mut combined: Option<u64> = None;
        for (size, checksum) in parts {
            let bytes = STANDARD.decode(checksum?).ok()?;
            if bytes.len() != width {
                return None;
            }
            let value = bytes
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            combined = Some(match combined {
                None => value,
                Some(before) => crc_fast::checksum_combine(crc, before, value, size),
            });
        }
        let combined = combined?.to_be_bytes();
        Some(STANDARD.encode(&combined[8 - width..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checksum of `data` in `algorithm`, base64.
    fn checksum(algorithm: &str, data: &[u8]) -> String {
        let mut hasher = ChecksumHasher::default();
        upload::enable(&mut hasher, algorithm);
        hasher.update(data);
        upload::field(&hasher.finalize(), algorithm)
            .clone()
            .unwrap()
    }

    /// The parts of Ceph's s3-tests: 5 MiB each of `A`, `B` and `C`.
    fn parts() -> Vec<Vec<u8>> {
        b"ABC"
            .iter()
            .map(|&byte| vec![byte; 5 * 1024 * 1024])
            .collect()
    }

    fn of(upload: UploadChecksum, parts: &[Vec<u8>]) -> String {
        let sums: Vec<String> = parts
            .iter()
            .map(|part| checksum(upload.algorithm, part))
            .collect();
        upload
            .of_parts(
                parts
                    .iter()
                    .zip(&sums)
                    .map(|(part, sum)| (part.len() as u64, Some(sum.as_str()))),
            )
            .unwrap()
    }

    #[test]
    fn checksums_of_parts_match_s3_tests() {
        let parts = parts();
        let upload = |algorithm, checksum_type| {
            UploadChecksum::requested(Some(algorithm), checksum_type)
                .unwrap()
                .unwrap()
        };
        assert_eq!(checksum("CRC32", &parts[0]), "JRTCyQ==");
        assert_eq!(of(upload("CRC32", Some("FULL_OBJECT")), &parts), "WgDhBQ==");
        assert_eq!(
            of(upload("CRC32C", Some("FULL_OBJECT")), &parts),
            "xU+Krw=="
        );
        assert_eq!(of(upload("CRC64NVME", None), &parts), "i+6LR0y3eFo=");
        assert_eq!(
            of(upload("SHA1", None), &parts),
            "sizjvY4eud3MrcHdZM3cQ/ol39o=-3"
        );
        assert_eq!(
            of(upload("SHA256", Some("COMPOSITE")), &parts),
            "uWBwpe1dxI4Vw8Gf0X9ynOdw/SS6VBzfWm9giiv1sf4=-3"
        );
        assert_eq!(
            of(upload("SHA256", None), &[vec![b'A'; 1024]]),
            "Ok6Cs5b96ux6+MWQkJO7UBT5sKPBeXBLwvj/hK89smg=-1"
        );
    }

    #[test]
    fn full_object_crcs_are_the_crc_of_the_content() {
        let parts = [b"hello ".to_vec(), Vec::new(), b"world".to_vec()];
        for algorithm in ["CRC32", "CRC32C", "CRC64NVME"] {
            let upload = UploadChecksum::requested(Some(algorithm), Some("FULL_OBJECT"))
                .unwrap()
                .unwrap();
            assert_eq!(
                of(upload, &parts),
                checksum(algorithm, b"hello world"),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn types_follow_the_algorithm() {
        let requested = |algorithm, checksum_type| {
            UploadChecksum::requested(algorithm, checksum_type)
                .map(|upload| upload.map(UploadChecksum::type_name))
        };
        assert_eq!(requested(None, None).unwrap(), None);
        assert!(requested(None, Some("COMPOSITE")).is_err());
        assert_eq!(requested(Some("crc32"), None).unwrap(), Some("COMPOSITE"));
        assert_eq!(
            requested(Some("CRC64NVME"), None).unwrap(),
            Some("FULL_OBJECT")
        );
        assert!(requested(Some("CRC64NVME"), Some("COMPOSITE")).is_err());
        assert!(requested(Some("SHA256"), Some("FULL_OBJECT")).is_err());
        assert!(requested(Some("MD5"), None).is_err());
        assert!(requested(Some("CRC32"), Some("OTHER")).is_err());
    }

    #[test]
    fn parts_without_checksums_give_none() {
        let upload = UploadChecksum::requested(Some("CRC32"), Some("FULL_OBJECT"))
            .unwrap()
            .unwrap();
        assert_eq!(upload.of_parts([(3, None)].into_iter()), None);
        assert_eq!(upload.of_parts([(3, Some("AAAA"))].into_iter()), None);
    }
}
