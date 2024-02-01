//! Trait for deriving child keys on a given type.

use crate::{PublicKey, KEY_SIZE};
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};

#[cfg(feature = "ed25519")]
use crate::XPrv;

/// Bytes which represent a private key.
pub type PrivateKeyBytes = [u8; KEY_SIZE];

/// Trait for key types which can be derived using BIP32.
pub trait PrivateKey: Sized {
    /// Public key type which corresponds to this private key.
    type PublicKey: PublicKey;

    /// Initialize this key from bytes.
    fn from_bytes(bytes: &PrivateKeyBytes) -> Self;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> PrivateKeyBytes;

    /// Derive a child key from a parent key and the a provided tweak value,
    /// i.e. where `other` is referred to as "I sub L" in BIP32 and sourced
    /// from the left half of the HMAC-SHA-512 output.
    fn derive_child(&self, other: PrivateKeyBytes) -> Self;

    /// Get the [`Self::PublicKey`] that corresponds to this private key.
    fn public_key(&self) -> Self::PublicKey;
}

#[cfg(feature = "ed25519")]
impl PrivateKey for Scalar {
    type PublicKey = RistrettoPoint;

    fn from_bytes(bytes: &PrivateKeyBytes) -> Self {
        Scalar::from_bytes_mod_order((*bytes).into())
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        self.to_bytes()
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Self {
        let child_scalar = Scalar::from_bytes_mod_order(other.into());
        let derived_scalar = self + child_scalar;
        derived_scalar
    }

    fn public_key(&self) -> Self::PublicKey {
        &constants::RISTRETTO_BASEPOINT_TABLE * self
    }
}

#[cfg(feature = "ed25519")]
impl From<&XPrv> for Scalar {
    fn from(xprv: &XPrv) -> Scalar {
        *xprv.private_key()
    }
}
