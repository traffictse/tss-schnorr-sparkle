// inspired by the PoC code from https://git.uwaterloo.ca/ckomlo/frost

use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256}; // for commitments
use sha3::{Digest as OtherDigest, Sha3_256}; // for signing
use std::{collections::HashMap, convert::TryInto, iter::zip};
use zeroize::Zeroize;

use crate::exn;
use xuanmi_base_support::*;

/// `/src/algo/hash.rs` implements a generic `generate_hash(hasher, components)`
/// to fullfil the role of the following 3 seperate hash-associted functions
/// in Sparkle, i.e., `generate_dkg_challenge` in KeyGen,
/// and `generate_hash_commitment` & `generate_hash_signing` in Sign.
///
/// Remind that, due to some technical issues, `generate_hash()` adopts
/// `Sha3_256` and `Keccak256` as two hash choices rather than
/// `sha2::Sha256` and `Sha3_256` in the following 3 functions
pub fn generate_dkg_challenge(
    index: &u16,
    context: &str,
    public: &RistrettoPoint,
    commitment: &RistrettoPoint,
) -> Outcome<Scalar> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(commitment.compress().to_bytes());
    hasher.update(public.compress().to_bytes());
    hasher.update(index.to_string());
    hasher.update(context);
    let result = hasher.finalize();

    let a: [u8; 32] = result.as_slice().try_into().catch(
        exn::HashException,
        "Failed to generate challenge for KeyGen",
    )?;

    Ok(Scalar::from_bytes_mod_order(a))
}

pub fn generate_hash_commitment(
    msg: &[u8],
    signers: &Vec<u16>,
    &group_nonce: &RistrettoPoint,
) -> Outcome<Scalar> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    let string_result = String::from_utf16_lossy(signers);
    hasher.update(msg);
    hasher.update(string_result);
    hasher.update(group_nonce.compress().to_bytes());
    let result = hasher.finalize();

    let a: [u8; 32] = result.as_slice().try_into().catch(
        exn::HashException,
        "Failed to generate hash for commitments",
    )?;

    Ok(Scalar::from_bytes_mod_order(a))
}

pub fn generate_hash_signing(
    msg: &[u8],
    group_public: &RistrettoPoint,
    &group_nonce: &RistrettoPoint,
) -> Outcome<Scalar> {
    let mut hasher = Sha3_256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(group_public.compress().to_bytes());
    hasher.update(msg);
    hasher.update(group_nonce.compress().to_bytes());
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .catch(exn::HashException, "Failed to generate hash for signing")?;

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

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct SigningKey {
    pub index: u16,
    pub x_i: Scalar,
    pub g_x_i: RistrettoPoint,
    pub group_public: RistrettoPoint,
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

impl Zeroize for KeyGenZKP {
    fn zeroize(&mut self) {
        self.g_k_i.zeroize();
        self.sigma_i.zeroize();
    }
}

impl Zeroize for SharesCommitment {
    fn zeroize(&mut self) {
        self.commitment.iter_mut().for_each(Zeroize::zeroize);
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
    pub fn is_valid_zkp(&self, challenge: Scalar) -> Outcome<()> {
        if self.zkp.g_k_i
            != (&constants::RISTRETTO_BASEPOINT_TABLE * &self.zkp.sigma_i)
                - (self.get_commitment_to_secret() * challenge)
        {
            throw!(
                name = exn::SignatureException,
                ctx =
                    &format!("Proof of knowledge (Schnorr signature) to the key share is invalid")
            );
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
    fn verify_share(&self, com: &SharesCommitment) -> Outcome<()> {
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
            throw!(
                name = exn::CommitmentException,
                ctx = &format!("Commitment to the key share is invalid")
            );
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
    ) -> Outcome<(SharesCommitment, Vec<Share>)> {
        if threshold < 1 || numshares < 1 || threshold > numshares {
            throw!(
                name = exn::ConfigException,
                ctx = &format!(
                    "Threshold or the number of shares cannot be 0,\t\nthreshold cannot exceed the number of shares,\t\nwhile threshold={} and number of shares={} are given",
                    threshold, numshares,
                )
            );
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
    ) -> Outcome<KeyGenZKP> {
        let k_i = Scalar::random(rng);
        let g_k_i = &constants::RISTRETTO_BASEPOINT_TABLE * &k_i;
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
    ) -> Outcome<(Vec<u16>, Vec<KeyGenCommitment>)> {
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
    ) -> Outcome<SigningKey> {
        // first, verify the integrity of the shares
        for share in &party_shares {
            let commitment = shares_com_vec
                .iter()
                .find(|comm| comm.index == share.generator_index)
                .if_none(
                    exn::CommitmentException,
                    "Received key share has no corresponding commitment",
                )?;
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
    ) -> Outcome<(Nonce, Scalar, RistrettoPoint)> {
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
    ) -> Outcome<SigningResponse> {
        for (com_i, decom_i) in zip(com_vec, decom_vec) {
            let com = generate_hash_commitment(msg, signers, decom_i)?;
            if com != *com_i {
                throw!(
                    name = exn::CommitmentException,
                    ctx = &format!("Commitment to the local nonce is invalid")
                );
            }
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
    ) -> Outcome<Signature> {
        if signing_decommitments.len() != signing_responses.len() {
            throw!(
                name = exn::AggregationException,
                ctx = &format!("Mismatched number of commitments and responses")
            );
        }
        let group_nonce = signing_decommitments.iter().sum();
        let challenge = generate_hash_signing(msg, &self.group_public, &group_nonce)?;

        // check the validity of each participant's response
        for resp in signing_responses {
            let lambda_i = get_lagrange_coeff(0, resp.index, signers)?;

            let decom_pos = signers.iter().position(|&x| x == resp.index).unwrap();
            let decom_i = signing_decommitments[decom_pos];
            let signer_pubkey = signer_pubkeys.get(&resp.index).if_none(
                exn::CommitmentException,
                "Commitment does not have a matching signer public key",
            )?;
            if !resp.is_valid(&signer_pubkey, lambda_i, &decom_i, challenge) {
                throw!(
                    name = exn::SignatureException,
                    ctx = &format!(
                        "Response from party_id={} is an invalid signature",
                        &resp.index,
                    )
                );
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
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Outcome<Nonce> {
        let secret = Scalar::random(rng);
        let public = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;
        if public == RistrettoPoint::identity() {
            throw!(
                name = exn::CommitmentException,
                ctx = &format!("Invalid nonce commitment")
            );
        }
        Ok(Nonce { secret, public })
    }
}

impl Signature {
    /// validate performs a plain Schnorr validation operation; this is identical
    /// to performing validation of a Schnorr signature that has been signed by a
    /// single party.
    pub fn validate(&self, pubkey: &RistrettoPoint) -> Outcome<()> {
        let challenge = generate_hash_signing(&self.hash, pubkey, &self.r)?;
        if self.r != (&constants::RISTRETTO_BASEPOINT_TABLE * &self.z) - (pubkey * challenge) {
            throw!(
                name = exn::SignatureException,
                ctx = &format!("Aggregated signature is invalid")
            );
        }
        Ok(())
    }
}

/// Generate the lagrange coefficient for the ith participant.
/// This allows performing Lagrange interpolation, which underpins
/// threshold secret sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(
    x_coord: u16,
    signer_index: u16,
    all_signer_indices: &[u16],
) -> Outcome<Scalar> {
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
        throw!(
            name = exn::ConfigException,
            ctx = &format!("Duplicate key shares provided")
        );
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

/// get g_x_i locally
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
