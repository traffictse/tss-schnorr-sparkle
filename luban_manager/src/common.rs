use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgressQuery {
    pub total: usize,
    pub rounds: Vec<i64>,
    pub values: Vec<String>,
}
