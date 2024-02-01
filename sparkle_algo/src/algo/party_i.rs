// inspired by the PoC code from https://git.uwaterloo.ca/ckomlo/frost

use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::convert::TryInto;
use std::iter::zip;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256}; // for commitments
use sha3::{Digest as OtherDigest, Sha3_256}; // for signing

// #[derive(Debug)]
// enum Value<'a> {
//     U16(&'a u16),
//     Str(&'a str),
//     Point(&'a RistrettoPoint),
//     Scalar(&'a Scalar),
//     Vec(&'a Vec<u16>)
//     // Add more variants for other types as needed
// }

// pub trait ToBytes {
//     fn to_bytes(&self) -> &[u8];
// }

// impl ToBytes for Value<'_> {
//     fn to_bytes(&self) -> &[u8] {
//         match self {
//             Value::U16(val) => val.to_be_bytes(),
//             Value::Str(val) => val.bytes(),
//             Value::Point(val) => val.compress().to_bytes(),
//             Value::Scalar(val) => val.as_bytes(),
//             Value::Vec(val) => unsafe {
//                 core::slice::from_raw_parts(
//                     val.as_ptr() as *const u8,
//                     val.len() * core::mem::size_of::<u16>(),
//                 )
//             },
//             // Add more cases for other types as needed
//         }
//     }
// }

// impl<T: ToBytes + ?Sized> ToBytes for &T {
//     fn to_bytes(&self) -> &[u8] {
//         (*self).to_bytes()
//     }
// }

// impl ToBytes for RistrettoPoint {
//     fn to_bytes(&self) -> &[u8] {
//         &self.compress().to_bytes()
//     }
// }

// impl ToBytes for Scalar {
//     fn to_bytes(&self) -> &[u8] {
//         self.as_bytes()
//     }
// }

// impl ToBytes for u16 {
//     fn to_bytes(&self) -> &[u8] {
//         &self.to_be_bytes()
//     }
// }

// impl ToBytes for [u16] {
//     fn to_bytes(&self) -> &[u8] {
//         unsafe {
//             core::slice::from_raw_parts(
//                 self.as_ptr() as *const u8,
//                 self.len() * core::mem::size_of::<u16>(),
//             )
//         }
//     }
// }

// impl ToBytes for &Vec<u16> {
//     fn to_bytes(&self) -> &[u8] {
//         unsafe {
//             core::slice::from_raw_parts(
//                 self.as_ptr() as *const u8,
//                 self.len() * core::mem::size_of::<u16>(),
//             )
//         }
//     }
// }

// impl ToBytes for &str {
//     fn to_bytes(&self) -> &[u8] {
//         self.as_bytes()
//     }
// }

// impl ToBytes for String {
//     fn to_bytes(&self) -> &[u8] {
//         self.as_bytes()
//     }
// }

// impl ToBytes for &[u8] {
//     fn to_bytes(&self) -> &[u8] {
//         self
//     }
// }

// pub trait HashFunction {
//     fn update<T: ToBytes + ?Sized>(&mut self, data: &T);
//     fn finalize(&self) -> &[u8];
// }

// impl HashFunction for Sha256 {
//     fn update<T: ToBytes + ?Sized>(&mut self, data: &T) {
//         self.update(data.to_bytes());
//     }

//     fn finalize(&self) -> &[u8] {
//         self.clone().finalize().as_slice()
//     }
// }

// impl HashFunction for Sha3_256 {
//     fn update<T: ToBytes + ?Sized>(&mut self, data: &T) {
//         self.update(data.to_bytes());
//     }

//     fn finalize(&self) -> &[u8] {
//         self.clone().finalize().as_slice()
//     }
// }

// pub fn generate_hash<'a, H, Args>(
//     mut hasher: H,
//     values: Args,
// ) -> Result<Scalar, &'static str>
// where
//     H: HashFunction,
//     Args: AsRef<[&'a (dyn ToBytes + 'a)]>,
// {
//     for value in values.as_ref() {
//         // hasher.update(value);
//         match value {
//             Value::U16(val) => hasher.update(val),
//             Value::Str(val) => hasher.update(val),
//             // Add more cases for other types as needed
//         }
//     }

//     let result = hasher.finalize();

//     let a: [u8; 32] = result
//         .as_slice()
//         .try_into()
//         .expect("Error in generating commitment!");

//     Ok(Scalar::from_bytes_mod_order(a))
// }

pub fn generate_dkg_challenge(
    index: &u16,
    context: &str,
    public: &RistrettoPoint,
    commitment: &RistrettoPoint,
) -> Result<Scalar, &'static str> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(commitment.compress().to_bytes());
    hasher.update(public.compress().to_bytes());
    hasher.update(index.to_string());
    hasher.update(context);
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");

    Ok(Scalar::from_bytes_mod_order(a))
}

pub fn generate_hash_commitment(
    msg: &[u8],
    signers: &Vec<u16>,
    &group_nonce: &RistrettoPoint,
) -> Result<Scalar, &'static str> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    let string_result = String::from_utf16_lossy(signers);
    hasher.update(msg);
    // hasher.update(&signers.iter().flat_map(|&x| vec![(x >> 8) as u8, (x & 0xFF) as u8]).collect::<u8>());
    hasher.update(string_result);
    hasher.update(group_nonce.compress().to_bytes());
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");

    Ok(Scalar::from_bytes_mod_order(a))
}

pub fn generate_hash_signing(
    msg: &[u8],
    group_public: &RistrettoPoint,
    &group_nonce: &RistrettoPoint,
) -> Result<Scalar, &'static str> {
    let mut hasher = Sha3_256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(group_public.compress().to_bytes());
    hasher.update(msg);
    hasher.update(group_nonce.compress().to_bytes());
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");

    Ok(Scalar::from_bytes_mod_order(a))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesCommitment {
    pub commitment: Vec<RistrettoPoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenProposedCommitment {
    pub index: u16,
    pub shares_commitment: SharesCommitment,
    pub zkp: KeyGenZKP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenCommitment {
    pub index: u16,
    pub shares_commitment: SharesCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share {
    generator_index: u16,
    pub receiver_index: u16,
    value: Scalar,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PartyKey {
    pub index: u16,
    pub u_i: Scalar,
    pub g_u_i: RistrettoPoint,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct SigningKey {
    pub index: u16,
    pub x_i: Scalar,
    pub g_x_i: RistrettoPoint,
    pub group_public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenZKP {
    pub g_k_i: RistrettoPoint, // KeyGen: g_k_i
    pub sigma_i: Scalar,       // KeyGen: sigma_i
}

#[derive(Copy, Clone)]
pub struct Nonce {
    secret: Scalar,
    pub public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitment {
    pub index: u16,
    pub com: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningDecommitment {
    pub index: u16,
    pub g_r_i: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningResponse {
    pub index: u16,
    pub response: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: RistrettoPoint, // Sign: R
    pub z: Scalar,         // Sign: z
    pub hash: Vec<u8>,     // Sign: hashed message
}

impl Zeroize for KeyGenProposedCommitment {
    fn zeroize(&mut self) {
        self.index.zeroize();
        self.shares_commitment.zeroize();
        self.zkp.zeroize();
    }
}

impl Zeroize for SharesCommitment {
    fn zeroize(&mut self) {
        self.commitment.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl Zeroize for KeyGenZKP {
    fn zeroize(&mut self) {
        self.g_k_i.zeroize();
        self.sigma_i.zeroize();
    }
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.generator_index.zeroize();
        self.receiver_index.zeroize();
        self.value.zeroize();
    }
}

impl KeyGenProposedCommitment {
    pub fn is_valid_zkp(&self, challenge: Scalar) -> Result<(), &'static str> {
        if self.zkp.g_k_i
            != (&constants::RISTRETTO_BASEPOINT_TABLE * &self.zkp.sigma_i)
                - (self.get_commitment_to_secret() * challenge)
        {
            return Err("Signature is invalid");
        }

        Ok(())
    }

    pub fn get_commitment_to_secret(&self) -> RistrettoPoint {
        self.shares_commitment.commitment[0]
    }
}

impl Share {
    pub fn new_from(generator_index: u16, receiver_index: u16, value: Scalar) -> Self {
        Self {
            generator_index,
            receiver_index,
            value,
        }
    }

    pub fn get_value(&self) -> Scalar {
        self.value
    }

    /// Verify that a share is consistent with a commitment.
    fn verify_share(&self, com: &SharesCommitment) -> Result<(), &'static str> {
        let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &self.value;

        let term = Scalar::from(self.receiver_index);
        let mut result = RistrettoPoint::identity();

        // Thanks to isis lovecruft for their simplification to Horner's method;
        // including it here for readability. Their implementation of FROST can
        // be found here: github.com/isislovecruft/frost-dalek
        for (index, comm_i) in com.commitment.iter().rev().enumerate() {
            result += comm_i;

            if index != com.commitment.len() - 1 {
                result *= term;
            }
        }

        if !(f_result == result) {
            return Err("Share is invalid.");
        }

        Ok(())
    }
}

impl PartyKey {
    pub fn new<R: RngCore + CryptoRng>(index: u16, rng: &mut R) -> Self {
        let u_i = Scalar::random(rng);
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        Self { index, u_i, g_u_i }
    }

    pub fn create_from<R: RngCore + CryptoRng>(u_i: Scalar, index: u16) -> Self {
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        Self { index, u_i, g_u_i }
    }

    /// Create secret shares for a given secret. This function accepts a secret to
    /// generate shares from. While in Sparkle this secret should always be generated
    /// randomly, we allow this secret to be specified for this internal function
    /// for testability
    pub fn generate_shares<R: RngCore + CryptoRng>(
        &self,
        numshares: u16,
        threshold: u16,
        rng: &mut R,
    ) -> Result<(SharesCommitment, Vec<Share>), &'static str> {
        if threshold < 1 {
            return Err("Threshold cannot be 0");
        }
        if numshares < 1 {
            return Err("Number of shares cannot be 0");
        }
        if threshold > numshares {
            return Err("Threshold cannot exceed numshares");
        }

        let numcoeffs = threshold;
        let mut coefficients = (0..numcoeffs)
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>();

        let commitment = coefficients.iter().fold(vec![self.g_u_i], |mut acc, c| {
            acc.push(&constants::RISTRETTO_BASEPOINT_TABLE * &c);
            acc
        });

        let shares = (1..=numshares)
            .map(|index| {
                // Evaluate the polynomial with `secret` as the constant term
                // and `coeffs` as the other coefficients at the point x=share_index
                // using Horner's method
                let scalar_index = Scalar::from(index);
                let mut value = Scalar::zero();
                for i in (0..numcoeffs).rev() {
                    value += &coefficients[i as usize];
                    value *= scalar_index;
                }
                // The secret is the *constant* term in the polynomial used for
                // secret sharing, this is typical in schemes that build upon Shamir
                // Secret Sharing.
                value += self.u_i;
                Share {
                    generator_index: self.index,
                    receiver_index: index,
                    value,
                }
            })
            .collect::<Vec<_>>();
        coefficients.iter_mut().for_each(|c| c.zeroize());
        Ok((SharesCommitment { commitment }, shares))
    }

    /// Create a zero-knowledge proof of knowledge to his own secret term by a classic Schnorr signature
    /// where `context` is introduced to prevent replay attacks
    pub fn keygen_generate_zkp<R: RngCore + CryptoRng>(
        &self,
        context: &str,
        rng: &mut R,
    ) -> Result<KeyGenZKP, &'static str> {
        let k_i = Scalar::random(rng);
        let g_k_i = &constants::RISTRETTO_BASEPOINT_TABLE * &k_i;
        // let challenge = generate_dkg_challenge(self.index, context, &self.g_u_i, &g_k)?;
        let challenge = generate_dkg_challenge(&self.index, context, &self.g_u_i, &g_k_i)?;
        let sigma_i = k_i + &self.u_i * challenge;
        Ok(KeyGenZKP { g_k_i, sigma_i })
    }

    /// Gather commitments from peers, validate the zero knowledge proof of knowledge
    /// for the peer's secret term, and return a list of participants who failed the check,
    /// a list of commitments for the peers that remain valid, and an error term.
    ///
    /// Here, we return a DKG commitmentment that is explicitly marked as valid,
    /// to ensure that this step is performed before going on to the construction of
    /// signing keys
    pub fn keygen_receive_commitments_and_validate_peers(
        peer_commitments: Vec<KeyGenProposedCommitment>,
        context: &str,
    ) -> Result<(Vec<u16>, Vec<KeyGenCommitment>), &'static str> {
        let mut invalid_peer_ids = Vec::new();
        let mut valid_peer_commitments: Vec<KeyGenCommitment> =
            Vec::with_capacity(peer_commitments.len());

        for commitment in peer_commitments {
            let challenge = generate_dkg_challenge(
                &commitment.index,
                context,
                &commitment.get_commitment_to_secret(),
                &commitment.zkp.g_k_i,
            )?;

            if !commitment.is_valid_zkp(challenge).is_ok() {
                invalid_peer_ids.push(commitment.index);
            } else {
                valid_peer_commitments.push(KeyGenCommitment {
                    index: commitment.index,
                    shares_commitment: commitment.shares_commitment,
                });
            }
        }

        Ok((invalid_peer_ids, valid_peer_commitments))
    }

    pub fn keygen_verify_share_construct_signingkey(
        party_shares: Vec<Share>,
        shares_com_vec: Vec<KeyGenCommitment>,
        index: u16,
    ) -> Result<SigningKey, &'static str> {
        // first, verify the integrity of the shares
        for share in &party_shares {
            let commitment = shares_com_vec
                .iter()
                .find(|comm| comm.index == share.generator_index)
                .ok_or("Received share with no corresponding commitment")?;
            share.verify_share(&commitment.shares_commitment)?;
        }

        let x_i = party_shares
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x.value);
        let g_x_i = &constants::RISTRETTO_BASEPOINT_TABLE * &x_i;

        let group_public = shares_com_vec
            .iter()
            .map(|c| c.shares_commitment.commitment[0])
            .fold(RistrettoPoint::identity(), |acc, x| acc + x);

        Ok(SigningKey {
            index,
            x_i,
            g_x_i,
            group_public,
        })
    }
}

impl SigningKey {
    /// Sample a local nonce that will finally contribute to the nonce in Schnorr signature
    /// and construct a commitment to the local nonce
    pub fn sign_sample_nonce_and_commit<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
        signers: &Vec<u16>,
    ) -> Result<(Nonce, Scalar, RistrettoPoint), &'static str> {
        let nonce = Nonce::new(rng)?;
        let com = generate_hash_commitment(msg, signers, &nonce.public)?;
        Ok((nonce, com, nonce.public.clone()))
    }

    /// Verify peer commitments to local nonces from each signer
    /// and generate a response (i.e., signature share) to the signature aggregator
    pub fn sign_decommit_and_respond(
        &self,
        msg: &[u8],
        signers: &Vec<u16>,
        com_vec: &Vec<Scalar>,
        decom_vec: &Vec<RistrettoPoint>,
        nonce: &Nonce,
    ) -> Result<SigningResponse, &'static str> {
        for (com_i, decom_i) in zip(com_vec, decom_vec) {
            let com = generate_hash_commitment(msg, signers, decom_i)?;
            assert_eq!(com, *com_i);
        }
        let group_nonce = decom_vec.iter().sum();
        let c = generate_hash_signing(msg, &self.group_public, &group_nonce)?;
        let lambda_i = get_lagrange_coeff(0, self.index, signers)?;

        let response = nonce.secret + (c * lambda_i * self.x_i);
        Ok(SigningResponse {
            index: self.index, // party id
            response,          // z_i = r_i + c * lambda_i * x_i
        })
    }

    /// Collect all responses from participants. It first performs a
    /// validity check for each participant's response, and will return an error in the
    /// case the response is invalid. If all responses are valid, it aggregates these
    /// into a single signature that is published.
    ///
    /// Although this function is executed by the entity performing the signature aggregator role,
    /// any signer if needed can invoke it to obtain the aggregated signature.
    pub fn sign_aggregate_responses(
        &self,
        msg: &[u8],
        signers: &Vec<u16>,
        signing_decommitments: &Vec<RistrettoPoint>,
        signing_responses: &Vec<SigningResponse>,
        signer_pubkeys: &HashMap<u16, RistrettoPoint>,
    ) -> Result<Signature, &'static str> {
        if signing_decommitments.len() != signing_responses.len() {
            return Err("Mismatched number of commitments and responses");
        }
        // // first, make sure that each decommitment corresponds to exactly one response
        // let mut decommitment_indices = signing_decommitments
        //     .iter()
        //     .map(|decom| decom.index)
        //     .collect::<Vec<u16>>();
        // let mut response_indices = signing_responses
        //     .iter()
        //     .map(|resp| resp.index)
        //     .collect::<Vec<u16>>();

        // decommitment_indices.sort();
        // response_indices.sort();

        // if decommitment_indices != response_indices {
        //     return Err("Mismatched commitment without corresponding response");
        // }

        let group_nonce = signing_decommitments.iter().sum();
        let challenge = generate_hash_signing(msg, &self.group_public, &group_nonce)?;

        // check the validity of each participant's response
        for resp in signing_responses {
            // let indices = signing_decommitments
            //     .iter()
            //     .map(|item| item.index)
            //     .collect::<Vec<_>>();

            let lambda_i = get_lagrange_coeff(0, resp.index, signers)?;

            let decom_pos = signers.iter().position(|&x| x == resp.index).unwrap();
            let decom_i = signing_decommitments[decom_pos];
            // .find(|x| x.index == resp.index)
            // .ok_or("No matching commitment for response")?;

            let signer_pubkey = signer_pubkeys
                .get(&resp.index)
                .ok_or("commitment does not have a matching signer public key!")?;

            if !resp.is_valid(&signer_pubkey, lambda_i, &decom_i, challenge) {
                return Err("Invalid signer response");
            }
        }

        let group_resp = signing_responses
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x.response);

        Ok(Signature {
            r: group_nonce,
            z: group_resp,
            hash: msg.to_vec(),
        })
    }
}

impl SigningResponse {
    pub fn is_valid(
        &self,
        pubkey: &RistrettoPoint,
        lambda_i: Scalar,
        commitment: &RistrettoPoint,
        challenge: Scalar,
    ) -> bool {
        (&constants::RISTRETTO_BASEPOINT_TABLE * &self.response)
            == (commitment + (pubkey * (challenge * lambda_i)))
    }
}

impl Nonce {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Nonce, &'static str> {
        let secret = Scalar::random(rng);
        let public = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;
        if public == RistrettoPoint::identity() {
            return Err("Invalid nonce commitment");
        }
        Ok(Nonce { secret, public })
    }
}

/// Generate the lagrange coefficient for the ith participant.
/// This allows performing Lagrange interpolation, which underpins
/// threshold secret sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(
    x_coord: u16,
    signer_index: u16,
    all_signer_indices: &[u16],
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices {
        if *j == signer_index {
            continue;
        }
        num *= Scalar::from(*j) - Scalar::from(x_coord);
        den *= Scalar::from(*j) - Scalar::from(signer_index);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

// get g_x_i locally
pub fn get_ith_pubkey(index: u16, commitments: &Vec<KeyGenCommitment>) -> RistrettoPoint {
    let mut ith_pubkey = RistrettoPoint::identity();
    let term = Scalar::from(index);

    // iterate over each commitment
    for commitment in commitments {
        let mut result = RistrettoPoint::identity();
        let t = commitment.shares_commitment.commitment.len() as u16;
        // iterate over each element in the commitment
        for (inner_index, comm_i) in commitment
            .shares_commitment
            .commitment
            .iter()
            .rev()
            .enumerate()
        {
            result += comm_i;

            // handle constant term
            if inner_index as u16 != t - 1 {
                result *= term;
            }
        }

        ith_pubkey += result;
    }

    ith_pubkey
}

/// to be reviewed again? For H(m, R) instead of H(R, Y, m)??? Classic Schnorr?
/// *******************************
/// generates the challenge value H(m, R) used for both signing and verification.
/// ed25519_ph hashes the message first, and derives the challenge as H(H(m), R),
/// this would be a better optimization but incompatibility with other
/// implementations may be undesirable

/// validate performs a plain Schnorr validation operation; this is identical
/// to performing validation of a Schnorr signature that has been signed by a
/// single party.
pub fn validate(sig: &Signature, pubkey: &RistrettoPoint) -> Result<(), &'static str> {
    let challenge = generate_hash_signing(&sig.hash, pubkey, &sig.r)?;
    if sig.r != (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - (pubkey * challenge) {
        return Err("Signature is invalid");
    }

    Ok(())
}
