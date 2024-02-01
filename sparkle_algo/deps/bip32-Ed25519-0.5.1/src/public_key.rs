//! Trait for deriving child keys on a given type.

use crate::{KeyFingerprint, PrivateKeyBytes, Result, KEY_SIZE};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[cfg(feature = "ed25519")]
use {
    crate::{Error, XPub},
    curve25519_dalek::{
        constants,
        ristretto::{CompressedRistretto, RistrettoPoint},
    },
};

/// Bytes which represent a public key.
///
/// Includes an extra byte for an SEC1 tag.
// pub type PublicKeyBytes = [u8; KEY_SIZE + 1];
pub type PublicKeyBytes = [u8; KEY_SIZE];

/// Trait for key types which can be derived using BIP32.
pub trait PublicKey: Sized {
    /// Initialize this key from bytes.
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self>;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> PublicKeyBytes;

    /// Derive a child key from a parent key and a provided tweak value.
    fn derive_child(&self, other: PrivateKeyBytes) -> Self;

    /// Compute a 4-byte key fingerprint for this public key.
    ///
    /// Default implementation uses `RIPEMD160(SHA256(public_key))`.
    fn fingerprint(&self) -> KeyFingerprint {
        let digest = Ripemd160::digest(Sha256::digest(self.to_bytes()));
        digest[..4].try_into().expect("digest truncated")
    }
}

#[cfg(feature = "ed25519")]
impl PublicKey for RistrettoPoint {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(&bytes);
        let pk = CompressedRistretto(tmp);
        Option::from(pk.decompress()).ok_or(Error::Decode)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        self.compress().to_bytes()
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Self {
        let child_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(other.into());
        let child_point = self + &constants::RISTRETTO_BASEPOINT_TABLE * &child_scalar;
        child_point
    }
}

#[cfg(feature = "ed25519")]
impl From<&XPub> for RistrettoPoint {
    fn from(xpub: &XPub) -> RistrettoPoint {
        *xpub.public_key()
    }
}
