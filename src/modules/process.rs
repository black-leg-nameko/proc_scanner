use std::fs;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SecretFinding {
    pub pid: i32,
    pub kind: String,
    pub value: String,
}

pub fn collect_secrets() -> Vec<SecretFinding> {
    let mut out = Vec::new();
    if let Ok(dir) = fs::read_dir("/proc") {
        for ent in dir.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            let pid: i32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            let cmd_path = ent.path().join("cmdline");
            if let Ok(data) = fs::read(cmd_path) {
                let s = String::from_utf8_lossy(&data);
                let joined = s.split('\0').filter(|x|!x.is_empty()).collect::<Vec<_>>().join(" ");
                if looks_sensitive(&joined) {
                    out.push(SecretFinding { pid, kind: "cmdline".to_string(), value: truncate(&joined, 512) });
                }
            }
            let env_path = ent.path().join("environ");
            if let Ok(data) = fs::read(env_path) {
                let envs = String::from_utf8_lossy(&data);
                for kv in envs.split('\0').filter(|x|!x.is_empty()) {
                    if looks_sensitive(kv) {
                        out.push(SecretFinding { pid, kind: "env".to_string(), value: truncate(kv, 512) });
                    }
                }
            }
        }
    }
    out
}

fn looks_sensitive(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let keys = [
        "password","passwd","pass","pwd","secret","token","apikey","api_key","api-key",
        "access_key","accesskey","secret_key","secretkey","auth","credential","session",
        "aws_access_key_id","aws_secret_access_key","db_user","db_pass","db_password","jdbc:"
    ];
    for k in keys.iter() { if lower.contains(k) { return true; } }
    false
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}...", &s[..n]) }
}
