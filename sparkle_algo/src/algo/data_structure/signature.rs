use crate::Signature;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

use super::{
    bytes_from_hex, bytes_to_hex, point_from_hex, point_to_hex, scalar_from_hex, scalar_to_hex,
};

impl Signature {
    pub fn new(r: &RistrettoPoint, z: Scalar, hash: &[u8]) -> Signature {
        Signature {
            r: *r,
            z,
            hash: hash.to_vec(),
        }
    }

    pub fn from_json(json: &str) -> Outcome<Signature> {
        let ss: SignatureSerde = json_to_obj(json)?;
        let so = Signature {
            r: point_from_hex(&ss.r)?,
            z: scalar_from_hex(&ss.z)?,
            hash: bytes_from_hex(&ss.hash)?,
        };
        Ok(so)
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: point_to_hex(&self.r),
            z: scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: point_to_hex(&self.r),
            z: scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json_pretty(&ss)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SignatureSerde {
    r: String,    // RistrettoPoint-hex:blahblah
    z: String,    // Scalar-hex:blahblah
    hash: String, // bytes-hex:blahblah
}
