use serde::{Deserialize, Serialize};
use std::thread;
use xuanmi_base_support::*;

pub type MpcResponse<T> = core::result::Result<T, String>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub party_id: u16,
    pub uuid: String,
}

pub const PARTY_ID_BCAST: u16 = 0;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Index {
    pub party_from: u16,
    pub party_to: u16,
    pub round: u16,
    pub uuid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Index,
    pub value: String,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct Params {
//     pub threshold: u16,
//     pub n_actual: u16,
//     pub n_keygen: u16,
// }
#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsG {
    /// -1 + Number of minimal sign parties.
    pub threshold: u16,
    /// Number of actual sign parties.
    pub n_actual: u16,
    /// Number of keygen parties.
    pub n_keygen: u16,
    /// session, code, ...
    pub uuid: String,
}

#[allow(unused_attributes)]
pub struct MpcClientMessenger {
    server: String,
    cmd: &'static str,
    uuid: String,
    threshold: u16,
    n_actual: u16,
    n_keygen: u16,
    my_id: u16,
    sleep_ms: u64,
}

const EX: &'static str = "MpcClientException";
const DEFAULT_POLL_SLEEP_MS: u64 = 200;
impl MpcClientMessenger {
    /// 一般情况下不必调用此函数. 开发或调试阶段需要.
    pub fn uuid<'a>(&'a self) -> &'a str {
        return self.uuid.as_str();
    }

    /// 获取由 MPC Manager 分配的 party_id.
    pub fn my_id(&self) -> u16 {
        return self.my_id;
    }

    /// 向 MPC Manager 登记名为 `cmd` 的业务. MPC Manager 将分配一个 party_id, 可通过 `self.my_id()` 读取它.
    /// 如果 `uuid` 采用调试后门, 例如 `2` , 则 MPC Manager 将重新分配 `uuid`, 可通过 `self.uuid()` 读取它.
    pub fn signup(
        server: &str,
        cmd: &'static str,
        uuid: &str,
        threshold: u16,
        n_actual: u16,
        n_keygen: u16,
    ) -> Outcome<MpcClientMessenger> {
        let mut msn = MpcClientMessenger {
            server: server.to_string(),
            cmd,
            uuid: uuid.to_string(),
            threshold,
            n_actual,
            n_keygen,
            my_id: 0,
            sleep_ms: match std::env::var("LUBAN_POLL_SLEEP_MS") {
                Err(_) => DEFAULT_POLL_SLEEP_MS,
                Ok(__) => match __.parse::<u64>() {
                    Ok(ms) => ms,
                    Err(_) => DEFAULT_POLL_SLEEP_MS,
                },
            },
        };
        let tn_params = ParamsG {
            threshold,
            n_actual,
            n_keygen,
            uuid: uuid.to_string(),
        };
        // If use dummy(debug) session, the session id will change;
        // otherwise, the session id will not change.
        let (my_id, uuid) = {
            let ps_res: MpcResponse<PartySignup> = http_post(
                &format!("{}/signup{}", msn.server, msn.cmd), 
                &tn_params,
            ).catch(
                EX,
                &format!(
                    "Failed to sign-up a {} transaction with server=\"{}\", uuid=\"{}\", t={}, n={}",
                    cmd, &msn.server, uuid, threshold, n_keygen
                )
            )?;
            let ps = match ps_res {
                Ok(ps) => ps,
                Err(msg) => throw!(name=EX, ctx=&format!(
                    "When signing up with server=\"{}\", task=\"{}\", uuid=\"{}\", t={}, n={}, the server gives the following errmsg: \"\"\"\n{}\n\"\"\"",
                    &msn.server, cmd, uuid, threshold, n_keygen, &msg
                )),
            };
            (ps.party_id, ps.uuid)
        };
        msn.my_id = my_id;
        msn.uuid = uuid;
        Ok(msn)
    }

    /// 向其他方发送广播消息
    // pub fn send_broadcast(&self, round: u16, text: &str) -> Outcome<()> {
    pub fn send_broadcast(&self, party_from: u16, round: u16, text: &str) -> Outcome<()> {
        let entry = Entry {
            key: Index {
                // party_from: self.my_id,
                party_from,
                party_to: PARTY_ID_BCAST,
                round,
                uuid: self.uuid.to_string(),
            },
            value: text.to_string(),
        };
        let url = format!("{}/set", self.server);
        let resp: MpcResponse<()> = http_post(&url, &entry)?;
        match resp {
            Ok(_) => {
                return Ok(());
            }
            Err(msg) => {
                let ctx = format!(
                    "Bad response from url=\"{}\", response=\"\"\"\n{}\n\"\"\"",
                    &url, &msg
                );
                throw!(name = EX, ctx = &ctx);
            }
        }
    }

    /// 向指定一方发送消息.
    // pub fn send_p2p(&self, other_id: u16, round: i32, data: &str) -> Outcome<()> {
    pub fn send_p2p(&self, party_from: u16, party_to: u16, round: u16, data: &str) -> Outcome<()> {
        let entry = Entry {
            key: Index {
                // party_from: self.my_id,
                // party_to: other_id,
                party_from,
                party_to,
                round,
                uuid: self.uuid.clone(),
            },
            value: data.to_string(),
        };
        let url = format!("{}/set", &self.server);
        let resp: MpcResponse<()> = http_post(&url, &entry)
        .catch(
            EX,
            &format!(
                "Failed to send a p2p message from party_id={} to party_id={} \n\tat round={} in session_uuid={}",
                // self.my_id, other_id, round, &self.uuid
                party_from, party_to, round, &self.uuid
            )
        )?;
        match resp {
            Ok(_) => {
                return Ok(());
            }
            Err(msg) => {
                let ctx = format!(
                    "Bad response from url=\"{}\", response=\"\"\"\n{}\n\"\"\"",
                    &url, &msg
                );
                throw!(name = EX, ctx = &ctx);
            }
        }
    }

    /// 收取其他方的广播消息. 等待直到收齐.
    // pub fn recv_broadcasts(&self, round: u16) -> Vec<String> {
    pub fn recv_broadcasts(&self, party_from: u16, party_count: u16, round: u16) -> Vec<String> {
        let mut ret: Vec<String> = Vec::with_capacity(self.n_actual as usize - 1);
        // '_outer: for i in 1..=self.n_actual {
        '_outer: for i in 1..=party_count {
            // if i == self.my_id {
            if i == party_from {
                continue;
            } // 略过自己. 自己没必要广播给自己.
            let index = Index {
                party_from: i,
                party_to: PARTY_ID_BCAST,
                round,
                uuid: self.uuid.clone(),
            };
            'inner: loop {
                let res_entry: Outcome<MpcResponse<Entry>> =
                    http_post(&format!("{}/get", &self.server), &index);
                if let Ok(Ok(entry)) = res_entry {
                    ret.push(entry.value);
                    break 'inner;
                }
                thread::sleep(std::time::Duration::from_millis(self.sleep_ms));
            }
        }
        ret
    }

    /// 收取指定一方的消息. 等待直到收到.
    // pub fn recv_p2p(&self, other_id: u16, round: i32) -> String {
    pub fn recv_p2p(&self, party_from: u16, party_to: u16, round: u16) -> String {
        let index = Index {
            // party_from: other_id,
            // party_to: self.my_id,
            party_from,
            party_to,
            round,
            uuid: self.uuid.clone(),
        };
        loop {
            let res_entry: Outcome<MpcResponse<Entry>> =
                http_post(&format!("{}/get", &self.server), &index);
            if let Ok(Ok(entry)) = res_entry {
                return entry.value;
            }
            thread::sleep(std::time::Duration::from_millis(self.sleep_ms));
        }
    }

    /// 收取所有其他方的消息. 等待直到收齐.
    // pub fn gather_p2p(&self, party_to: u16, party_count: u16, round: i32) -> Vec<String> {
    pub fn gather_p2p(&self, party_to: u16, party_count: u16, round: u16) -> Vec<String> {
        // let mut ret: Vec<String> = Vec::with_capacity(self.n_actual as usize - 1);
        let mut ret: Vec<String> = Vec::with_capacity(party_count as usize - 1);
        // for other_id in 1..=self.n_actual {
        for party_from in 1..=party_count {
            // if other_id == self.my_id {
            if party_from == party_to {
                continue;
            }
            // ret.push(self.recv_p2p(other_id, round));
            ret.push(self.recv_p2p(party_from, party_to, round));
        }
        ret
    }
}
