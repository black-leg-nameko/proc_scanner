use serde::Serialize;
use serde_json;

use super::network::SocketEntry;
use super::privilege::PrivFinding;
use super::fd::CrossFinding;
use super::process::SecretFinding;

#[derive(Debug, Serialize)]
pub struct Report {
    pub network: Vec<SocketEntry>,
    pub privileges: Vec<PrivFinding>,
    pub cross: Vec<CrossFinding>,
    pub secrets: Vec<SecretFinding>,
}

pub fn to_json(rep: &Report) -> String {
    serde_json::to_string_pretty(rep).unwrap_or_else(|_| "{}".to_string())
}
