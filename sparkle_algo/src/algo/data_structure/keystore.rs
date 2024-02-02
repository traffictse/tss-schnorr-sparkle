use serde::{Deserialize, Serialize};
use serde_json;
use xuanmi_base_support::*;

use crate::exn;
use crate::{KeyGenCommitment, PartyKey, SharesCommitment, SigningKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub party_key: PartyKey,
    pub signing_key: SigningKey,
    pub party_num_int: u16,
    pub valid_com_vec: Vec<KeyGenCommitment>,
}

impl KeyStore {
    pub fn to_json(&self) -> Outcome<String> {
        let ser = serialize_friendly::KeyStore::serialize(self);
        let json = serde_json::to_string(&ser).catch(exn::ObjectToJsonException, "")?;
        Ok(json)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ser = serialize_friendly::KeyStore::serialize(self);
        let json = serde_json::to_string_pretty(&ser).catch(exn::ObjectToJsonException, "")?;
        Ok(json)
    }

    pub fn from_json(json: &str) -> Outcome<Self> {
        let ser: serialize_friendly::KeyStore =
            serde_json::from_str(json).catch(exn::JsonToObjectException, "")?;
        let obj: KeyStore = ser.deserialize()?;
        Ok(obj)
    }
}

mod serialize_friendly {
    use super::super::{point_from_hex, point_to_hex, scalar_from_hex, scalar_to_hex};
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde::{Deserialize, Serialize};
    use xuanmi_base_support::Outcome;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PartyKey {
        pub index: u16,
        pub u_i: String,   // scalar_hex
        pub g_u_i: String, // RistrettoPoint_hex
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SigningKey {
        pub index: u16,
        pub x_i: String,          // Scalar_hex
        pub g_x_i: String,        // RistrettoPoint_hex
        pub group_public: String, // RistrettoPoint_hex
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SharesCommitment {
        pub commitment: Vec<String>, // Vec<RistrettoPoint_hex>
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct KeyGenCommitment {
        pub index: u16,
        pub shares_commitment: SharesCommitment, // SharesCommitment_hex
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeyStore {
        pub party_key: PartyKey,
        pub signing_key: SigningKey,
        pub party_num_int: u16, // Not u16???
        pub valid_com_vec: Vec<KeyGenCommitment>,
    }

    impl KeyStore {
        pub fn serialize(src: &super::KeyStore) -> Self {
            KeyStore {
                party_key: PartyKey {
                    index: src.party_key.index,
                    u_i: scalar_to_hex(&src.party_key.u_i),
                    g_u_i: point_to_hex(&src.party_key.g_u_i),
                },
                signing_key: SigningKey {
                    index: src.signing_key.index,
                    x_i: scalar_to_hex(&src.signing_key.x_i),
                    g_x_i: point_to_hex(&src.signing_key.g_x_i),
                    group_public: point_to_hex(&src.signing_key.group_public),
                },
                party_num_int: src.party_num_int,
                valid_com_vec: {
                    let valid_com_vec_str: Vec<KeyGenCommitment> = src
                        .valid_com_vec
                        .iter()
                        .map(|x| KeyGenCommitment {
                            index: x.index,
                            shares_commitment: SharesCommitment {
                                commitment: x
                                    .shares_commitment
                                    .commitment
                                    .iter()
                                    .map(|y| point_to_hex(&y))
                                    .collect::<Vec<String>>(),
                            },
                        })
                        .collect::<Vec<_>>();
                    valid_com_vec_str
                },
            }
        }

        pub fn deserialize(&self) -> Outcome<super::KeyStore> {
            let ret = super::KeyStore {
                party_key: super::PartyKey {
                    index: self.party_key.index,
                    u_i: scalar_from_hex(&self.party_key.u_i)?,
                    g_u_i: point_from_hex(&self.party_key.g_u_i)?,
                },
                signing_key: super::SigningKey {
                    index: self.signing_key.index,
                    x_i: scalar_from_hex(&self.signing_key.x_i)?,
                    g_x_i: point_from_hex(&self.signing_key.g_x_i)?,
                    group_public: point_from_hex(&self.signing_key.group_public)?,
                },
                party_num_int: self.party_num_int,
                valid_com_vec: {
                    let mut valid_com_vec_from_hex: Vec<super::KeyGenCommitment> = Vec::new();
                    for valid_com in self.valid_com_vec.iter() {
                        let ele = super::KeyGenCommitment {
                            index: valid_com.index,
                            shares_commitment: super::SharesCommitment {
                                commitment: {
                                    let com: Vec<RistrettoPoint> = valid_com
                                        .shares_commitment
                                        .commitment
                                        .iter()
                                        .map(|y| point_from_hex(y))
                                        .collect::<Result<Vec<RistrettoPoint>, _>>()?;
                                    com
                                },
                            },
                        };
                        valid_com_vec_from_hex.push(ele);
                    }
                    valid_com_vec_from_hex
                },
            };
            Ok(ret)
        }
    }
}
