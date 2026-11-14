//! Signed statements (protocol 2.3): data the server must carry unchanged between devices, or
//! that proves a device holds its key.
//!
//! A [`Signed`] statement is the statement's UTF-8 JSON bytes, serialized once by the signer,
//! and an Ed25519 signature over `context ‖ 0x00 ‖ bytes`, both in base64url without padding.
//! [`Signed::open`] finds the signer's key in the statement, verifies the signature with
//! `verify_strict` semantics, and only then hands the statement out: nothing is acted on
//! before the signature holds.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh_base::{SecretKey, Signature};
use serde::{Deserialize, Serialize};

use super::{DeviceId, limits::MAX_STATEMENT_BYTES};

/// The `login` statement: a registering device proves its key (protocol 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    /// The server origin the device is talking to.
    pub server: String,
    /// The device.
    pub endpoint_id: DeviceId,
    /// The challenge of the registration, base64url.
    pub challenge: String,
}

/// The `hello` statement: a device opens the control channel (protocol 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The server origin.
    pub server: String,
    /// The account's username.
    pub account: String,
    /// The device.
    pub endpoint_id: DeviceId,
    /// The nonce of the server's `challenge`, base64url.
    pub nonce: String,
}

/// A device as a pairing statement describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    /// Its key.
    pub endpoint_id: DeviceId,
    /// Its name.
    pub name: String,
    /// Its platform.
    pub platform: String,
    /// Its product.
    pub product: String,
}

/// The `pair-request` statement: a new device asks to join the account's devices
/// (protocol 8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// The server origin.
    pub server: String,
    /// The account's username.
    pub account: String,
    /// The new device.
    pub requester: DeviceSummary,
    /// 32 random bytes, base64url.
    pub nonce: String,
    /// When it was made, UNIX seconds.
    pub issued_at: i64,
}

/// A device that an approval introduces (protocol 8.4). The flags are seen from the
/// introduced device, as in Input Show's `TrustedDevice`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Introduced {
    /// Its key.
    pub endpoint_id: DeviceId,
    /// Its name.
    pub name: String,
    /// The newcomer may control this device.
    pub allow_incoming: bool,
    /// This device may control the newcomer.
    pub allow_outgoing: bool,
}

/// The `pair-approval` statement: a directly paired device vouches for a newcomer
/// (protocol 8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairApproval {
    /// The server origin.
    pub server: String,
    /// The account's username.
    pub account: String,
    /// The approving device, which signs.
    pub approver: DeviceId,
    /// The newcomer.
    pub subject: DeviceSummary,
    /// The nonce of the `pair-request` statement.
    pub request_nonce: String,
    /// How the approver verified the newcomer: `remote-sas`.
    pub method: String,
    /// The devices the newcomer is introduced to, and they to it.
    pub introduced: Vec<Introduced>,
    /// When it was signed, UNIX seconds.
    pub issued_at: i64,
    /// When it stops being valid, at most 30 days later.
    pub expires_at: i64,
}

/// A statement of any kind. The JSON object carries its kind in `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Statement {
    /// See [`Login`].
    #[serde(rename = "login")]
    Login(Login),
    /// See [`Hello`].
    #[serde(rename = "hello")]
    Hello(Hello),
    /// See [`PairRequest`].
    #[serde(rename = "pair-request")]
    PairRequest(PairRequest),
    /// See [`PairApproval`].
    #[serde(rename = "pair-approval")]
    PairApproval(PairApproval),
}

impl Statement {
    /// The signature context of this kind (protocol 2.3).
    pub fn context(&self) -> &'static str {
        match self {
            Self::Login(_) => "gono-connect login v1",
            Self::Hello(_) => "gono-connect hello v1",
            Self::PairRequest(_) => "gono-connect pair-request v1",
            Self::PairApproval(_) => "gono-connect pair-approval v1",
        }
    }

    /// The device whose key signs this kind of statement.
    pub fn signer(&self) -> DeviceId {
        match self {
            Self::Login(login) => login.endpoint_id,
            Self::Hello(hello) => hello.endpoint_id,
            Self::PairRequest(request) => request.requester.endpoint_id,
            Self::PairApproval(approval) => approval.approver,
        }
    }
}

/// A statement as it travels: its bytes and its signature, both base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// The statement's bytes.
    pub statement: String,
    /// The Ed25519 signature, 64 bytes.
    pub signature: String,
}

/// Why a [`Signed`] statement was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatementError {
    /// Not base64url, too large, or not a statement.
    #[error("malformed statement")]
    Malformed,
    /// The signature does not hold for the signer the statement names.
    #[error("bad signature")]
    BadSignature,
}

/// The bytes a signature covers.
fn signed_bytes(context: &str, statement: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(context.len() + 1 + statement.len());
    bytes.extend_from_slice(context.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(statement);
    bytes
}

impl Signed {
    /// Serializes `statement` and signs it with `key`, which must be the key of
    /// [`Statement::signer`].
    pub fn sign(statement: &Statement, key: &SecretKey) -> Self {
        let bytes = serde_json::to_vec(statement).unwrap_or_default();
        let signature = key.sign(&signed_bytes(statement.context(), &bytes));
        Self {
            statement: URL_SAFE_NO_PAD.encode(&bytes),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    /// Verifies the signature against the signer the statement names and returns the
    /// statement.
    pub fn open(&self) -> Result<Statement, StatementError> {
        // Base64 grows by 4/3; refuse oversized input before decoding it.
        if self.statement.len() > MAX_STATEMENT_BYTES / 3 * 4 + 4 {
            return Err(StatementError::Malformed);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.statement)
            .map_err(|_| StatementError::Malformed)?;
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(StatementError::Malformed);
        }
        let signature: [u8; Signature::LENGTH] = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .ok()
            .and_then(|signature| signature.try_into().ok())
            .ok_or(StatementError::Malformed)?;
        let statement: Statement =
            serde_json::from_slice(&bytes).map_err(|_| StatementError::Malformed)?;
        statement
            .signer()
            .0
            .verify(
                &signed_bytes(statement.context(), &bytes),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| StatementError::BadSignature)?;
        Ok(statement)
    }
}

/// base64url without padding, the encoding of every byte string of the protocol.
pub fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
pub fn decode_bytes(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn hello(key: &SecretKey) -> Statement {
        Statement::Hello(Hello {
            server: "https://cloud.example.com".to_owned(),
            account: "kim".to_owned(),
            endpoint_id: key.public().into(),
            nonce: encode_bytes(&[1; 32]),
        })
    }

    #[test]
    fn signed_statements_open_for_their_signer_only() {
        let alice = key(1);
        let statement = hello(&alice);
        let signed = Signed::sign(&statement, &alice);
        assert_eq!(signed.open().unwrap(), statement);

        // Signed by another key than the one it names.
        let forged = Signed::sign(&statement, &key(2));
        assert_eq!(forged.open(), Err(StatementError::BadSignature));

        // The same bytes under another kind's context do not verify.
        let bytes = decode_bytes(&signed.statement).unwrap();
        let other_context = alice.sign(&signed_bytes("gono-connect login v1", &bytes));
        let wrong = Signed {
            statement: signed.statement.clone(),
            signature: encode_bytes(&other_context.to_bytes()),
        };
        assert_eq!(wrong.open(), Err(StatementError::BadSignature));

        // Changed bytes do not verify.
        let mut changed = String::from_utf8(bytes).unwrap();
        changed = changed.replace("kim", "mallory");
        let tampered = Signed {
            statement: encode_bytes(changed.as_bytes()),
            signature: signed.signature.clone(),
        };
        assert_eq!(tampered.open(), Err(StatementError::BadSignature));
    }

    #[test]
    fn malformed_statements_are_refused() {
        let alice = key(1);
        let signed = Signed::sign(&hello(&alice), &alice);
        for broken in [
            Signed {
                statement: "not base64!".to_owned(),
                signature: signed.signature.clone(),
            },
            Signed {
                statement: signed.statement.clone(),
                signature: encode_bytes(&[0; 10]),
            },
            Signed {
                statement: encode_bytes(br#"{"kind":"unknown"}"#),
                signature: signed.signature.clone(),
            },
            Signed {
                statement: encode_bytes(&vec![b' '; MAX_STATEMENT_BYTES + 1]),
                signature: signed.signature.clone(),
            },
        ] {
            assert_eq!(broken.open(), Err(StatementError::Malformed));
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let alice = key(1);
        let id = DeviceId::from(alice.public());
        let json = format!(
            r#"{{"kind":"login","server":"https://c.example","endpoint_id":"{id}","challenge":"AA","later":1}}"#
        );
        let signature = alice.sign(&signed_bytes("gono-connect login v1", json.as_bytes()));
        let signed = Signed {
            statement: encode_bytes(json.as_bytes()),
            signature: encode_bytes(&signature.to_bytes()),
        };
        assert!(matches!(signed.open().unwrap(), Statement::Login(_)));
    }
}
