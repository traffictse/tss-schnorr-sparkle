#![deny(unused_results, unused_must_use)]
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
mod algo;
pub use algo::*;
mod exceptions;
pub use exceptions::exception_names as exn;

const SignUpFailed: &str = "SignUpFailed";
const InvalidMessage: &str = "InvalidMessage";
const InvalidConfigs: &str = "InvalidConfigs";
const InvalidKeystore: &str = "InvalidKeystore";
const InvalidSignature: &str = "InvalidSignature";
const InvalidKeyGenZKP: &str = "InvalidKeyGenZKP";
const InvalidCommitment: &str = "InvalidCommitment";
const SharesGenFailed: &str = "SharesGenFailed";
const KeyGenPoKGenFailed: &str = "KeyGenPoKGenFailed";
const SignFailed: &str = "SignFailed";
const SignatureAggregateFailed: &str = "SignatureAggregateFailed";
const SigningComGenFailed: &str = "SigningComGenFailed";
const DKGChallengeGenFailed: &str = "DKGChallengeGenFailed";
