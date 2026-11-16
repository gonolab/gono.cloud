//! Secrets the server must be able to read back, stored encrypted.
//!
//! Most secrets are stored only as digests ([`crate::secret`]). Some cannot be: a TOTP check
//! recomputes codes from the secret, and an S3 signature (SigV4) is an HMAC keyed with it. Those
//! are sealed with a [`Key`] that lives outside the database directory, in the file of
//! `two_factor.key_file`, so a copy of the database alone gives none of them away.
//!
//! - ChaCha20-Poly1305 (ring) with a random 96-bit nonce, stored before the ciphertext:
//!   `nonce ‖ ciphertext ‖ tag`.
//! - The associated data is the [`Purpose`]'s context string followed by the id of the row
//!   the secret belongs to (8 bytes, big endian). A sealed secret therefore opens only for the
//!   purpose and the row it was sealed for: it cannot be copied to another account, nor be
//!   passed off as a secret of another kind. The context strings differ in length, so the
//!   associated data of two purposes can never be equal.
//!
//! The associated data of [`Purpose::Totp`] is the one described in
//! `docs/connect-protocol.md` section 13.6; it must not change, or existing enrolments stop
//! opening.

use std::{
    fs,
    io::{self, Write as _},
    path::Path,
};

use rand::RngExt as _;
use ring::aead;

use crate::error::{Error, Result};

/// What a sealed secret is for, and so what its id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The TOTP secret of an account; the id is the user id.
    Totp,
    /// The secret of an S3 access key; the id is the key's app password id.
    S3Secret,
}

impl Purpose {
    /// The associated data before the id. Never change a published value.
    fn context(self) -> &'static [u8] {
        match self {
            Self::Totp => b"gono-cloud totp v1",
            Self::S3Secret => b"gono-cloud s3 secret v1",
        }
    }

    fn aad(self, id: i64) -> aead::Aad<Vec<u8>> {
        let mut aad = self.context().to_vec();
        aad.extend_from_slice(&id.to_be_bytes());
        aead::Aad::from(aad)
    }
}

/// The key secrets are sealed with: 32 bytes from a file of the configuration directory (raw
/// bytes, or 64 hex digits).
#[derive(Clone)]
pub struct Key(aead::LessSafeKey);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Key {
    /// A key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // CHACHA20_POLY1305 takes exactly 32 bytes, so this cannot fail.
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
            .unwrap_or_else(|_| unreachable!("a 32-byte ChaCha20-Poly1305 key"));
        Self(aead::LessSafeKey::new(unbound))
    }

    /// Reads the key file at `path`. `None` if it does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(Error::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let key = parse_key(&bytes).ok_or_else(|| Error::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "the key file must hold 32 bytes or 64 hex digits",
            ),
        })?;
        Ok(Some(Self::from_bytes(&key)))
    }

    /// Creates the key file at `path` with 32 random bytes, readable by its owner and group
    /// only. Returns `false` if it exists already (a dangling symbolic link counts as
    /// existing): an existing key is never replaced, so read it with [`Key::load`].
    ///
    /// The key is written to a temporary file in the same directory, synced, and then linked
    /// to `path`, which fails if the name is taken. So a crash never leaves a partial key
    /// behind, and of two processes creating it at once, one wins and the other keeps its key.
    pub fn create(path: &Path) -> Result<bool> {
        let io_error = |source| Error::Io {
            path: path.to_path_buf(),
            source,
        };
        if path.symlink_metadata().is_ok() {
            return Ok(false);
        }
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let temp = dir.join(format!(".{name}.{:016x}.tmp", rand::rng().random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
        let mut file = options.open(&temp).map_err(io_error)?;
        let key: [u8; 32] = rand::rng().random();
        let linked = file
            .write_all(&key)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::hard_link(&temp, path));
        drop(file);
        // The key lives on under `path`, or the attempt failed: either way the temporary
        // name goes.
        let _ = fs::remove_file(&temp);
        match linked {
            Ok(()) => {
                // Best effort: make the new name durable too.
                #[cfg(unix)]
                if let Ok(dir) = fs::File::open(dir) {
                    let _ = dir.sync_all();
                }
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(io_error(err)),
        }
    }

    /// Encrypts `secret` for `purpose` and the row `id`: nonce ‖ ciphertext ‖ tag.
    pub fn seal(&self, purpose: Purpose, id: i64, secret: &[u8]) -> Vec<u8> {
        let nonce: [u8; aead::NONCE_LEN] = rand::rng().random();
        let mut sealed = secret.to_vec();
        // Sealing in place only fails for input of gigabytes, which no secret is.
        if self
            .0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                purpose.aad(id),
                &mut sealed,
            )
            .is_err()
        {
            return Vec::new();
        }
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        out
    }

    /// Decrypts what [`Key::seal`] produced for `purpose` and `id`; `None` for another key,
    /// another purpose, another row or damaged data.
    pub fn open(&self, purpose: Purpose, id: i64, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < aead::NONCE_LEN {
            return None;
        }
        let (nonce, ciphertext) = sealed.split_at(aead::NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buffer = ciphertext.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, purpose.aad(id), &mut buffer)
            .ok()?;
        Some(plain.to_vec())
    }
}

fn parse_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(key) = <[u8; 32]>::try_from(bytes) {
        return Some(key);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        key[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_secrets_open_only_for_their_key_purpose_and_row() {
        let key = Key::from_bytes(&[1; 32]);
        let sealed = key.seal(Purpose::Totp, 7, b"secret");
        assert_eq!(
            key.open(Purpose::Totp, 7, &sealed).as_deref(),
            Some(&b"secret"[..])
        );
        assert!(key.open(Purpose::Totp, 8, &sealed).is_none(), "another row");
        assert!(
            key.open(Purpose::S3Secret, 7, &sealed).is_none(),
            "another purpose"
        );
        assert!(
            Key::from_bytes(&[2; 32])
                .open(Purpose::Totp, 7, &sealed)
                .is_none(),
            "another key"
        );
        assert_ne!(
            sealed,
            key.seal(Purpose::Totp, 7, b"secret"),
            "a fresh nonce every time"
        );
        assert!(
            key.open(Purpose::Totp, 7, &sealed[..5]).is_none(),
            "damaged"
        );
    }

    #[test]
    fn purposes_never_share_associated_data() {
        // Equal lengths would let a context and an id of one purpose spell the associated
        // data of another.
        assert_ne!(
            Purpose::Totp.context().len(),
            Purpose::S3Secret.context().len()
        );
    }

    #[test]
    fn totp_associated_data_is_unchanged() {
        // docs/connect-protocol.md section 13.6: `gono-cloud totp v1` and the user id. A
        // secret sealed before sealing became generic must still open.
        let key = Key::from_bytes(&[4; 32]);
        let nonce = [9u8; aead::NONCE_LEN];
        let mut aad = b"gono-cloud totp v1".to_vec();
        aad.extend_from_slice(&42i64.to_be_bytes());
        let mut sealed = b"totp".to_vec();
        key.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut sealed,
            )
            .unwrap();
        let mut stored = nonce.to_vec();
        stored.extend_from_slice(&sealed);
        assert_eq!(
            key.open(Purpose::Totp, 42, &stored).as_deref(),
            Some(&b"totp"[..])
        );
    }

    #[test]
    fn key_files() {
        assert!(parse_key(&[3; 32]).is_some());
        assert!(parse_key("ab".repeat(32).as_bytes()).is_some());
        assert!(parse_key(format!("{}\n", "ab".repeat(32)).as_bytes()).is_some());
        assert!(parse_key(b"short").is_none());
    }
}
