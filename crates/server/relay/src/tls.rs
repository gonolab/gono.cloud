//! The certificate of QUIC address discovery, read again from disk on an interval.
//!
//! The reverse proxy owns the certificate of the relay's host name; a renewal hook (certbot's
//! deploy hook, a systemd path unit, a daily copy) puts a copy of the certificate and its key
//! where the relay reads them. Such hooks copy the two files one after the other, and some
//! renewal tools write them in place one after the other too, so a read can see the new
//! certificate with the old key. iroh-relay's `reloading_resolver` would serve that pair until
//! its next read, an hour later by default, and every QAD handshake would fail meanwhile.
//! [`CertificateFiles`] serves a pair only once both files parse and the key belongs to the
//! certificate; until then it keeps the pair it served so far.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use anyhow::{Context, bail};
use rustls::{
    InconsistentKeys,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::task::JoinHandle;

/// Serves the certificate in `cert` with the key in `key`, as read by the last good
/// [`CertificateFiles::reload`].
#[derive(Debug)]
pub(crate) struct CertificateFiles {
    cert: PathBuf,
    key: PathBuf,
    provider: Arc<CryptoProvider>,
    served: RwLock<Arc<CertifiedKey>>,
}

impl CertificateFiles {
    /// Reads the certificate and its key. Fails when they cannot be served: a file is missing
    /// or does not parse, or the key does not belong to the certificate.
    pub(crate) fn load(
        cert: &Path,
        key: &Path,
        provider: Arc<CryptoProvider>,
    ) -> anyhow::Result<Self> {
        let served = read_pair(cert, key, &provider)?;
        Ok(Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            provider,
            served: RwLock::new(Arc::new(served)),
        })
    }

    /// Reads both files again and serves them from now on if the certificate changed. Returns
    /// whether it did. On an error the pair served so far stays.
    pub(crate) fn reload(&self) -> anyhow::Result<bool> {
        let pair = read_pair(&self.cert, &self.key, &self.provider)?;
        let mut served = self.served.write().unwrap_or_else(PoisonError::into_inner);
        if served.cert == pair.cert {
            return Ok(false);
        }
        *served = Arc::new(pair);
        Ok(true)
    }

    /// Calls [`CertificateFiles::reload`] every `interval` until the returned handle is dropped,
    /// logging what changed and what failed.
    pub(crate) fn spawn_reloads(self: &Arc<Self>, interval: Duration) -> ReloadTask {
        let files = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut ticks =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                let reading = Arc::clone(&files);
                match tokio::task::spawn_blocking(move || reading.reload()).await {
                    Ok(Ok(true)) => tracing::info!(
                        cert = %files.cert.display(),
                        "relay certificate for QUIC address discovery reloaded"
                    ),
                    Ok(Ok(false)) => {}
                    Ok(Err(err)) => tracing::warn!(
                        error = %format!("{err:#}"),
                        "relay certificate not reloaded; QUIC address discovery keeps serving the \
                         certificate it read before"
                    ),
                    Err(err) => tracing::warn!(error = %err, "relay certificate reload failed"),
                }
            }
        });
        ReloadTask(task)
    }
}

impl ResolvesServerCert for CertificateFiles {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self.served.read().unwrap_or_else(PoisonError::into_inner),
        ))
    }
}

/// The task of [`CertificateFiles::spawn_reloads`]; dropping it stops the reloads.
#[derive(Debug)]
pub(crate) struct ReloadTask(JoinHandle<()>);

impl Drop for ReloadTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Reads the certificate chain in `cert` and the key in `key`, both PEM, and checks that they
/// belong together.
fn read_pair(cert: &Path, key: &Path, provider: &CryptoProvider) -> anyhow::Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("read the certificate {}", cert.display()))?;
    if chain.is_empty() {
        bail!("{} holds no certificate", cert.display());
    }
    let private_key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("read the key {}", key.display()))?;
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .with_context(|| format!("load the key {}", key.display()))?;
    let pair = CertifiedKey::new(chain, signing_key);
    match pair.keys_match() {
        // Key types whose public key rustls cannot derive are not checked.
        Ok(()) | Err(rustls::Error::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(pair),
        Err(err) => bail!(
            "the key {} does not belong to the certificate {} ({err}); was only one of them \
             replaced?",
            key.display(),
            cert.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate for `localhost` and its key, as PEM.
    fn certificate() -> (String, String) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (certified.cert.pem(), certified.signing_key.serialize_pem())
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn served(files: &CertificateFiles) -> Vec<CertificateDer<'static>> {
        files.served.read().unwrap().cert.clone()
    }

    fn der(pem: &str) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()]
    }

    #[test]
    fn a_renewal_is_served_once_both_files_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("fullchain.pem"),
            dir.path().join("privkey.pem"),
        );
        let (old_cert, old_key) = certificate();
        std::fs::write(&cert, &old_cert).unwrap();
        std::fs::write(&key, &old_key).unwrap();
        let files = CertificateFiles::load(&cert, &key, provider()).unwrap();
        assert!(!files.reload().unwrap(), "nothing changed");

        // The hook has copied the new certificate, but not its key yet.
        let (new_cert, new_key) = certificate();
        std::fs::write(&cert, &new_cert).unwrap();
        let err = files.reload().unwrap_err();
        assert!(format!("{err:#}").contains("does not belong"), "{err:#}");
        assert_eq!(served(&files), der(&old_cert), "the old pair stays");

        // A key file caught while it is written does not parse.
        std::fs::write(&key, "").unwrap();
        files.reload().unwrap_err();
        assert_eq!(served(&files), der(&old_cert), "the old pair stays");

        std::fs::write(&key, &new_key).unwrap();
        assert!(files.reload().unwrap(), "the renewal is served");
        assert_eq!(served(&files), der(&new_cert));
    }

    #[test]
    fn a_key_of_another_certificate_is_refused_at_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("fullchain.pem"),
            dir.path().join("privkey.pem"),
        );
        std::fs::write(&cert, certificate().0).unwrap();
        std::fs::write(&key, certificate().1).unwrap();
        let err = CertificateFiles::load(&cert, &key, provider()).unwrap_err();
        assert!(format!("{err:#}").contains("does not belong"), "{err:#}");
    }

    #[test]
    fn an_empty_certificate_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("fullchain.pem"),
            dir.path().join("privkey.pem"),
        );
        std::fs::write(&cert, "").unwrap();
        std::fs::write(&key, certificate().1).unwrap();
        let err = CertificateFiles::load(&cert, &key, provider()).unwrap_err();
        assert!(
            format!("{err:#}").contains("holds no certificate"),
            "{err:#}"
        );
    }
}
