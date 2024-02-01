#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use luban_core::MpcClientMessenger;
use xuanmi_base_support::*;

use super::party_i::*;
// use super::party_i::{Signature, SigningResponse};

use super::data_structure::KeyStore;
use crate::{
    InvalidConfigs, InvalidKeystore, InvalidMessage, InvalidSignature, SignFailed, SignUpFailed,
    SignatureAggregateFailed, SigningComGenFailed,
};

pub fn algo_sign(
    server: &str,
    tr_uuid: &str,
    tcn_config: &[u16; 3],
    msg_hashed: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    if msg_hashed.len() > 64 {
        let mut msg =
            String::from("The sign algorithm **assumes** its input message has been hashed.\n");
        msg += &format!("However, the algorithm received a message with length = {}, indicating the message is probably un-hashed.\n", msg_hashed.len());
        msg += "Did the caller forget to hash the message?";
        throw!(name = InvalidMessage, ctx = &msg);
    }

    let (threshold, parties, share_count) = (tcn_config[0], tcn_config[1], tcn_config[2]);
    let signing_key = keystore.signing_key;
    let valid_com_vec = keystore.valid_com_vec.clone();
    let party_id = keystore.party_num_int;
    println!(
        "Start sign with threshold={}, parties={}, share_count={}",
        threshold, parties, share_count,
    );
    let cond = threshold + 1 <= parties && parties <= share_count;
    if !cond {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/c/n config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                threshold, parties, share_count
            )
        );
    }

    // #region signup for signing
    let messenger =
        MpcClientMessenger::signup(server, "sign", tr_uuid, threshold, parties, share_count)
            .catch(
                SignUpFailed,
                &format!(
                    "Cannot sign up for key geneation with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server {} designated this party with\n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let exception_location = &format!(
        " (at party_id={}, tr_uuid={}).",
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    let mut rng = OsRng;
    // #endregion

    // #region round 1: collect signer IDs
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&party_id)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signers_vec: Vec<u16> = round1_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<u16>, _>>()?;
    if signers_vec.contains(&party_id) {
        throw!(
            name = InvalidKeystore,
            ctx = &(format!("Duplicated keyshare") + exception_location)
        );
    }
    signers_vec.insert(party_num_int as usize - 1, party_id);
    // need to check if a signer is not in the list of valid_com_vec???
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 2: broadcast signing commitment to the nonce
    let (nonce, com, decom) =
        match signing_key.sign_sample_nonce_and_commit(&mut rng, msg_hashed, &signers_vec) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = SigningComGenFailed,
                ctx = &(("Failed to generate signing commitments").to_owned() + exception_location)
            ),
        };
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&com)?)?;
    let round2_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_com_vec: Vec<Scalar> = round2_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<Scalar>, _>>()?;
    signing_com_vec.insert(party_num_int as usize - 1, com.clone());
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 3: broadcast signing decommitment
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&decom)?)?;
    let round3_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_decom_vec: Vec<RistrettoPoint> = round3_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<RistrettoPoint>, _>>()?;
    signing_decom_vec.insert(party_num_int as usize - 1, decom.clone());
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 4: broadcast signing response
    let response_i: SigningResponse = match signing_key.sign_decommit_and_respond(
        msg_hashed,
        &signers_vec,
        &signing_com_vec,
        &signing_decom_vec,
        &nonce,
    ) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = SignFailed,
            ctx = &(format!("Failed to sign the message, particularly \"{}\"", err)
                + exception_location)
        ),
    };
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&response_i)?)?;
    let round4_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut response_vec: Vec<SigningResponse> = round4_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<SigningResponse>, _>>()?;
    response_vec.insert(party_num_int as usize - 1, response_i);
    println!("Finished sign round {round}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, RistrettoPoint> = HashMap::with_capacity(parties as usize);
    for counter in 0..parties as usize {
        let ith_pubkey = get_ith_pubkey(signers_vec[counter], &valid_com_vec);
        let _ = signer_pubkeys.insert(signers_vec[counter], ith_pubkey);
    }
    let group_sig: Signature = match signing_key.sign_aggregate_responses(
        msg_hashed,
        &signers_vec,
        &signing_decom_vec,
        &response_vec,
        &signer_pubkeys,
    ) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = SignatureAggregateFailed,
            ctx = &(format!(
                "Failed to aggregate signature shares, particularly \"{}\"",
                err
            ) + exception_location)
        ),
    };
    if !validate(&group_sig, &signing_key.group_public).is_ok() {
        throw!(
            name = InvalidSignature,
            ctx = &(format!("Invalid Schnorr signature") + exception_location)
        );
    }
    // #endregion

    println!("Finished sign");
    Ok(group_sig)
}
