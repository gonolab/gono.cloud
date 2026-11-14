//! [`DeviceId`]: a device's Ed25519 public key in its wire form.

use std::{fmt, str::FromStr};

use iroh_base::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A device's Ed25519 public key: its device ID and its iroh `EndpointId`.
///
/// On the wire it is exactly 64 lowercase hex digits (protocol 2.1); anything else, upper
/// case included, is refused. Parsing also refuses 32 bytes that are not a point on the curve.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(pub PublicKey);

/// Why a string is not a [`DeviceId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a device ID is 64 lowercase hex digits of an Ed25519 public key")]
pub struct InvalidDeviceId;

impl DeviceId {
    /// The 32 bytes of the key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The key of 32 bytes, if they are a valid Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, InvalidDeviceId> {
        PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| InvalidDeviceId)
    }

    /// 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(64);
        for byte in self.as_bytes() {
            hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
            hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        hex
    }

    /// The short ID shown to people: the first 8 bytes in upper-case hex, grouped in fours
    /// (`AB12-CD34-EF56-7890`).
    pub fn short(&self) -> String {
        let hex = self.to_hex()[..16].to_ascii_uppercase();
        let groups: Vec<&str> = (0..4).map(|i| &hex[i * 4..i * 4 + 4]).collect();
        groups.join("-")
    }
}

impl From<PublicKey> for DeviceId {
    fn from(key: PublicKey) -> Self {
        Self(key)
    }
}

impl FromStr for DeviceId {
    type Err = InvalidDeviceId;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return Err(InvalidDeviceId);
        }
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(InvalidDeviceId),
        };
        let mut key = [0u8; 32];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            key[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Self::from_bytes(&key)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = std::borrow::Cow::<str>::deserialize(deserializer)?;
        hex.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn device_ids_are_strict_lowercase_hex_keys() {
        let key = SecretKey::from_bytes(&[7; 32]).public();
        let id = DeviceId(key);
        let hex = id.to_hex();
        assert_eq!(hex.parse::<DeviceId>().unwrap(), id);
        assert_eq!(id.short().len(), 19);
        assert!(hex.to_ascii_uppercase().parse::<DeviceId>().is_err());
        assert!(hex[..62].parse::<DeviceId>().is_err());
        // 64 hex digits that are not a point on the curve.
        assert!("02".repeat(32).parse::<DeviceId>().is_err());
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{hex}\""));
        assert_eq!(
            serde_json::from_str::<DeviceId>(&format!("\"{hex}\"")).unwrap(),
            id
        );
    }
}
