use serde::{Deserialize, Serialize};
use sparkle_algo::*;
use xuanmi_base_support::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Task {
    Keygen(Keygen),
    Sign(Sign),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keygen {
    pub server: String,
    pub tr_uuid: String,
    pub tn_config: [u16; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub server: String,
    pub tr_uuid: String,
    pub tcn_config: [u16; 3],
    pub msg_hashed: String,
}

fn main() -> Outcome<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Expected 2 cmdline arguments [cmd_json_path, keystore_path], received {}",
            args.len() - 1
        );
        return Err(Exception::new());
    }

    let jpath = args[1].to_lexical_abspath()?;
    let kfpath = args[2].to_lexical_abspath()?;
    println!("JSON path: {}\nKeystore path: {}", &jpath, &kfpath);
    let json = read_str_from_file(&jpath)?;
    let task = json_to_obj(&json)?;

    match task {
        Task::Keygen(args) => {
            let keystore = algo_keygen(&args.server, &args.tr_uuid, &args.tn_config, "yaoguai")?;
            let keystore_json = keystore.to_json()?;
            let _ = write_str_to_file(&kfpath, &keystore_json)?;
        }
        Task::Sign(args) => {
            let keystore_json = read_str_from_file(&kfpath)?;
            let keystore = KeyStore::from_json(&keystore_json)?;
            let msg_hashed = bytes_from_hex(&args.msg_hashed)?;
            let signature = algo_sign(
                &args.server,
                &args.tr_uuid,
                &args.tcn_config,
                &msg_hashed,
                &keystore,
            )?;
            let signature_json = signature.to_json_pretty()?;
            println!("{}", &signature_json);
        }
    }

    return Ok(());
}
