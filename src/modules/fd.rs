use std::collections::{HashMap, HashSet};
use std::fs;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CrossFinding {
    pub pid: i32,
    pub uid: u32,
    pub caps: Vec<String>,
    pub inodes: Vec<u64>,
    pub cmd: String,
}

pub fn collect_cross_issues() -> Vec<CrossFinding> {
    let inode_to_pids = build_inode_to_pids_map();
    let mut out = Vec::new();
    if let Ok(dir) = fs::read_dir("/proc") {
        for ent in dir.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            let pid: i32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            let status = ent.path().join("status");
            let content = match fs::read_to_string(status) { Ok(s) => s, Err(_) => continue };
            let mut uid: u32 = 0;
            let mut cap_eff_hex = String::new();
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 { uid = parts[1].parse::<u32>().unwrap_or(0); }
                } else if line.starts_with("CapEff:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 { cap_eff_hex = parts[1].to_string(); }
                }
            }
            let caps_mask = u64::from_str_radix(cap_eff_hex.trim_start_matches("0x"), 16).unwrap_or(0);
            let caps = mask_to_caps(caps_mask).into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
            if suspicious_caps(&caps.iter().map(|s| s.as_str()).collect(), uid) {
                let inodes: Vec<u64> = inode_to_pids.iter().filter(|(_, set)| set.contains(&pid)).map(|(i, _)| *i).collect();
                if !inodes.is_empty() {
                    let cmd = read_cmdline(pid);
                    out.push(CrossFinding { pid, uid, caps, inodes, cmd });
                }
            }
        }
    }
    out
}

fn read_cmdline(pid: i32) -> String {
    let path = format!("/proc/{}/cmdline", pid);
    let data = match fs::read(path) { Ok(d) => d, Err(_) => return String::from("<unknown>") };
    let s = String::from_utf8_lossy(&data);
    let joined = s.split('\0').filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ");
    if joined.is_empty() { String::from("<unknown>") } else { joined }
}

fn suspicious_caps(caps: &Vec<&str>, uid: u32) -> bool {
    let hot: HashSet<&'static str> = [
        "CAP_SYS_ADMIN","CAP_SYS_MODULE","CAP_SYS_PTRACE","CAP_SYS_TIME","CAP_SYS_BOOT",
        "CAP_NET_ADMIN","CAP_SYS_RAWIO","CAP_SYS_NICE","CAP_SYS_CHROOT","CAP_SETUID","CAP_SETGID",
    ].into_iter().collect();
    if uid == 0 { return !caps.is_empty(); }
    for c in caps { if hot.contains(*c) { return true; } }
    false
}

fn build_inode_to_pids_map() -> HashMap<u64, HashSet<i32>> {
    let mut map: HashMap<u64, HashSet<i32>> = HashMap::new();
    if let Ok(proc_dir) = fs::read_dir("/proc") {
        for ent in proc_dir.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            let pid: i32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            let fd_dir = ent.path().join("fd");
            let iter = match fs::read_dir(fd_dir) { Ok(it) => it, Err(_) => continue };
            for fdent in iter.flatten() {
                let link = match fs::read_link(fdent.path()) { Ok(p) => p, Err(_) => continue };
                if let Some(s) = link.to_string_lossy().strip_prefix("socket:[") {
                    if let Some(end) = s.strip_suffix(']') {
                        if let Ok(inode) = end.parse::<u64>() {
                            map.entry(inode).or_default().insert(pid);
                        }
                    }
                }
            }
        }
    }
    map
}

fn mask_to_caps(mask: u64) -> Vec<&'static str> {
    let table: [&str; 64] = [
        "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER","CAP_FSETID","CAP_KILL",
        "CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE","CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW","CAP_IPC_LOCK","CAP_IPC_OWNER",
        "CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE","CAP_SYS_PACCT",
        "CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE","CAP_SYS_RESOURCE","CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG","CAP_MKNOD","CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL",
        "CAP_SETFCAP","CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON","CAP_BPF","CAP_CHECKPOINT_RESTORE",
        "CAP_41","CAP_42","CAP_43","CAP_44","CAP_45","CAP_46","CAP_47","CAP_48","CAP_49","CAP_50",
        "CAP_51","CAP_52","CAP_53","CAP_54","CAP_55","CAP_56","CAP_57","CAP_58","CAP_59","CAP_60",
        "CAP_61","CAP_62","CAP_63",
    ];
    let mut out = Vec::new();
    for i in 0..64 { if (mask >> i) & 1 == 1 { out.push(table[i]); } }
    out
}
