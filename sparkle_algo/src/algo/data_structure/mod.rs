mod keystore;
pub use keystore::*;
mod signature;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
pub use signature::*;
use xuanmi_base_support::{TraitStdResultToOutcome, *};

const BYTES_HEX: &'static str = "bytes_hex:";
const SCALAR_HEX: &'static str = "scalar_hex:";
const POINT_HEX: &'static str = "point_hex:";

pub fn bytes_from_hex(hex: &str) -> Outcome<Vec<u8>> {
    const ERR_BYTES: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < BYTES_HEX.len() {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BYTES);
    }
    if &hex[..BYTES_HEX.len()] != BYTES_HEX {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BYTES);
    }
    hex::decode(&hex[BYTES_HEX.len()..]).catch("HexToBytesException", "")
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::from(BYTES_HEX);
    hex_str.push_str(hex::encode(bytes).as_str());
    hex_str
}

pub fn scalar_from_hex(hex: &str) -> Outcome<Scalar> {
    const ERR_SCALAR: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < SCALAR_HEX.len() {
        throw!(name = "IncorrectPrefixError", ctx = ERR_SCALAR);
    }
    if &hex[..SCALAR_HEX.len()] != SCALAR_HEX {
        throw!(name = "IncorrectPrefixError", ctx = ERR_SCALAR);
    }
    let bytes = bytes_from_hex(&hex[SCALAR_HEX.len()..])?;
    let bytes: [u8; 32] = bytes.try_into().unwrap();
    Ok(Scalar::from_bytes_mod_order(bytes))
}

pub fn scalar_to_hex(scalar: &Scalar) -> String {
    let mut hex_str = String::from(SCALAR_HEX);
    hex_str.push_str(&bytes_to_hex(&scalar.to_bytes()));
    hex_str
}

pub fn point_from_hex(hex: &str) -> Outcome<RistrettoPoint> {
    const ERR_POINT: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < POINT_HEX.len() {
        throw!(name = "IncorrectPrefixError", ctx = ERR_POINT);
    }
    if &hex[..POINT_HEX.len()] != POINT_HEX {
        throw!(name = "IncorrectPrefixError", ctx = ERR_POINT);
    }
    CompressedRistretto::from_slice(&bytes_from_hex(&hex[POINT_HEX.len()..])?)
        .decompress()
        .if_none("HexToPointException", "")
}

pub fn point_to_hex(point: &RistrettoPoint) -> String {
    let mut hex_str = String::from(POINT_HEX);
    hex_str.push_str(&bytes_to_hex(&point.compress().to_bytes()));
    hex_str
}
