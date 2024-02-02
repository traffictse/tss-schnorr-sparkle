#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use luban_core::*;
use rand::rngs::OsRng;
use xuanmi_base_support::*;
use zeroize::Zeroize;

use super::aes;
use super::party_i::{KeyGenCommitment, KeyGenProposedCommitment, PartyKey, Share, SigningKey};
use crate::algo::data_structure::KeyStore;
use crate::exn;

type KeygenT = KeyStore; // keystore_json

pub fn algo_keygen(
    server: &str,
    tr_uuid: &str,
    tn_config: &[u16; 2],
    context: &str,
) -> Outcome<KeygenT> {
    // note that the string `context` is used to prevent replay attacks
    let (threshold, share_count, parties) = (tn_config[0], tn_config[1], tn_config[1]);
    println!(
        "Start keygen with \n\tthreshold={}, share_count={}",
        threshold, share_count,
    );
    if threshold >= share_count {
        throw!(
            name = exn::ConfigException,
            ctx = &format!(
                "t/n config should satisfy t<n.\n\tHowever, {}/{} were provided",
                threshold, share_count,
            )
        );
    }

    // #region signup for keygen
    let messenger =
        MpcClientMessenger::signup(server, "keygen", tr_uuid, threshold, parties, share_count)
            .catch(
                exn::SignUpException,
                &format!(
                    "Cannot sign up for key geneation with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server \"{}\" designated this party with \n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    // #endregion

    // #region generate commitment and zkp for broadcasting
    let mut rng = OsRng;
    let party_key = PartyKey::new(party_num_int, &mut rng);
    let (shares_com, mut shares) = match party_key.generate_shares(parties, threshold, &mut rng) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = exn::ConfigException,
            ctx = &(format!("Failed to generate key shares, particularly \"{}\"", err))
        ),
    };
    let zkp = match party_key.keygen_generate_zkp(context, &mut rng) {
        Ok(_ok) => _ok,
        Err(_) => throw!(
            name = exn::SignatureException,
            ctx = &format!("Failed to generate proof of knowledge to the key share")
        ),
    };

    let dkg_commitment = KeyGenProposedCommitment {
        index: party_num_int,
        shares_commitment: shares_com,
        zkp,
    };
    // #endregion

    // #region round 1: send public commitment to coeffs and a proof of knowledge to u_i
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&dkg_commitment)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut dkg_com_vec: Vec<KeyGenProposedCommitment> = round1_ans_vec
        .iter()
        .map(|m| json_to_obj(m))
        .collect::<Result<Vec<KeyGenProposedCommitment>, _>>()?;
    dkg_com_vec.insert(party_num_int as usize - 1, dkg_commitment);
    println!("Finished keygen round {round}");
    round += 1;
    // #endregion

    // #region verify commitment and zkp from round 1 and construct aes keys
    let (invalid_peer_ids, valid_com_vec): (Vec<u16>, Vec<KeyGenCommitment>) =
        match PartyKey::keygen_receive_commitments_and_validate_peers(dkg_com_vec.clone(), &context)
        {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = exn::HashException,
                ctx = &format!("Failed to generate challenge for KeyGen")
            ),
        };
    if invalid_peer_ids.len() > 0 {
        throw!(
            name = exn::SignatureException,
            ctx = &format!(
                "Invalid zkp to key shares from party_ids={:?}",
                invalid_peer_ids
            )
        );
    }
    dkg_com_vec.iter_mut().for_each(|x| x.zeroize());

    let mut enc_keys: Vec<RistrettoPoint> = Vec::new();
    for i in 1..=parties {
        if i != party_num_int {
            enc_keys.push(
                &valid_com_vec[i as usize - 1].shares_commitment.commitment[0] * &party_key.u_i,
            );
        }
    }
    // #endregion

    // #region round 2: send secret shares via aes-p2p
    let mut j = 0;
    for (k, i) in (1..=parties).enumerate() {
        if i != party_num_int {
            // prepare encrypted share for party i
            let key_i = &enc_keys[j].compress().to_bytes();
            let plaintext = shares[k].get_value().to_bytes();
            let aead_pack_i = aes::aes_encrypt(key_i, &plaintext)?;
            messenger.send_p2p(party_num_int, i, round, &obj_to_json(&aead_pack_i)?)?;
            j += 1;
        }
    }
    let round2_ans_vec = messenger.gather_p2p(party_num_int, parties, round);
    println!("Finished keygen round {round}");
    // #endregion

    // #region retrieve private signing key share
    let mut j = 0;
    let mut party_shares: Vec<Share> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            party_shares.push(shares[(i - 1) as usize].clone());
            shares.zeroize();
        } else {
            let aead_pack: aes::AEAD = json_to_obj(&round2_ans_vec[j])?;
            let key_i = &enc_keys[j].compress().to_bytes();
            let out = aes::aes_decrypt(key_i, &aead_pack)?;
            let mut out_arr = [0u8; 32];
            out_arr.copy_from_slice(&out);
            let out_fe = Share::new_from(i, party_num_int, Scalar::from_bytes_mod_order(out_arr));
            party_shares.push(out_fe);
            j += 1;
        }
    }

    let signing_key: SigningKey = match PartyKey::keygen_verify_share_construct_signingkey(
        party_shares.clone(),
        valid_com_vec.clone(),
        party_num_int,
    ) {
        Ok(_ok) => _ok,
        Err(_) => throw!(
            name = exn::CommitmentException,
            ctx = &format!("Invalid commitment to key share")
        ),
    };
    party_shares.iter_mut().for_each(|x| x.zeroize());
    // #endregion

    let keystore = KeyStore {
        party_key,
        signing_key,
        party_num_int,
        valid_com_vec,
    };
    println!("Finished keygen");
    Ok(keystore)
}
