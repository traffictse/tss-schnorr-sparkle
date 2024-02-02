/// Implement a generic function to fullfil the role
/// of the 3 seperate hash-associted functions in `/src/algo/party_i.rs`
/// i.e., `generate_dkg_challenge` in KeyGen,
/// and `generate_hash_commitment` & `generate_hash_signing` in Sign.
///
/// Remind that, due to some technical issues,
/// `generate_hash()` adopts `Sha3_256` and `Keccak256` as two hash choices
/// rather than `sha2::Sha256` and `Sha3_256` in the above 3 functions
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha3::{Digest, Keccak256, Sha3_256};
use std::convert::TryInto;

use crate::exn;
use xuanmi_base_support::*;

pub trait HashUpdater<D: Digest + Clone> {
    fn update_hash(&self, hasher: &mut D);
}

trait KeccakUpdater: HashUpdater<Keccak256> {}
trait Sha3Updater: HashUpdater<Sha3_256> {}

impl<T: KeccakUpdater + Sha3Updater> HashUpdater<Keccak256> for T {
    fn update_hash(&self, hasher: &mut Keccak256) {
        <dyn KeccakUpdater>::update_hash(self, hasher);
    }
}

impl<T: KeccakUpdater + Sha3Updater> HashUpdater<Sha3_256> for T {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        <dyn Sha3Updater>::update_hash(self, hasher);
    }
}

impl HashUpdater<Keccak256> for RistrettoPoint {
    fn update_hash(&self, hasher: &mut Keccak256) {
        hasher.update(self.compress().to_bytes());
    }
}

impl HashUpdater<Sha3_256> for RistrettoPoint {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        hasher.update(self.compress().to_bytes());
    }
}

impl HashUpdater<Keccak256> for u16 {
    fn update_hash(&self, hasher: &mut Keccak256) {
        hasher.update(self.to_string().as_bytes());
    }
}

impl HashUpdater<Sha3_256> for u16 {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        hasher.update(self.to_string().as_bytes());
    }
}

impl HashUpdater<Keccak256> for Vec<u16> {
    fn update_hash(&self, hasher: &mut Keccak256) {
        hasher.update(String::from_utf16_lossy(self));
    }
}

impl HashUpdater<Sha3_256> for Vec<u16> {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        hasher.update(String::from_utf16_lossy(self));
    }
}

impl HashUpdater<Keccak256> for &str {
    fn update_hash(&self, hasher: &mut Keccak256) {
        hasher.update(self);
    }
}

impl HashUpdater<Sha3_256> for &str {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        hasher.update(self);
    }
}

impl HashUpdater<Sha3_256> for &[u8] {
    fn update_hash(&self, hasher: &mut Sha3_256) {
        hasher.update(self);
    }
}

impl HashUpdater<Keccak256> for &[u8] {
    fn update_hash(&self, hasher: &mut Keccak256) {
        hasher.update(self);
    }
}

struct HashBuilder<'a, D: Digest + Clone> {
    hasher: D,
    components: Vec<&'a dyn HashUpdater<D>>,
}

impl<'a, D: Digest + Clone> HashBuilder<'a, D> {
    fn new(hasher: D) -> Self {
        HashBuilder {
            hasher,
            components: Vec::new(),
        }
    }

    fn update(&mut self, component: &'a dyn HashUpdater<D>) {
        self.components.push(component);
    }

    fn finalize(&mut self) -> Outcome<Scalar> {
        for component in &self.components {
            component.update_hash(&mut self.hasher);
        }

        let result = self.hasher.clone().finalize();
        let a: [u8; 32] = result
            .as_slice()
            .try_into()
            .catch(exn::HashException, "Failed to generate hash!")?;
        Ok(Scalar::from_bytes_mod_order(a))
    }
}

pub fn generate_hash<D: Digest + Clone>(
    hasher: D,
    components: Vec<&dyn HashUpdater<D>>,
) -> Outcome<Scalar> {
    let mut hash_builder = HashBuilder::new(hasher);
    for component in components {
        hash_builder.update(component);
    }
    hash_builder.finalize()
}

// Example usage:
#[cfg(test)]
mod tests {
    use super::*;

    fn generate_hash_works() {
        let some_point = RistrettoPoint::default();
        let some_u16 = 42u16;
        let some_vec = vec![1u16, 2u16, 3u16];
        let some_bytes = "bytes".as_bytes();
        let some_str = "string";

        let hash_result_1 = generate_hash(
            Keccak256::new(),
            vec![&some_point, &some_u16, &some_vec, &some_bytes, &some_str],
        )?;
        let hash_result_2 = generate_hash(
            Sha3_256::new(),
            vec![&some_point, &some_u16, &some_vec, &some_bytes, &some_str],
        )?;
        println!("One Hash Result: {:?}", hash_result_1);
        println!("Another Hash Result: {:?}", hash_result_2);
    }
}
