use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SocketEntry {
    pub proto: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub inode: u64,
    pub pids: Vec<i32>,
    pub score: i32,
}

pub fn collect_network() -> Vec<SocketEntry> {
    let inode_to_pids = build_inode_to_pids_map();
    let mut entries = Vec::new();
    entries.extend(read_tcp_table("/proc/net/tcp", "tcp", &inode_to_pids));
    entries.extend(read_tcp6_table("/proc/net/tcp6", "tcp6", &inode_to_pids));
    entries.extend(read_udp_table("/proc/net/udp", "udp", &inode_to_pids));
    entries.extend(read_udp6_table("/proc/net/udp6", "udp6", &inode_to_pids));
    entries
}

fn read_tcp_table(path: &str, proto: &str, inode_to_pids: &HashMap<u64, HashSet<i32>>) -> Vec<SocketEntry> {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return Vec::new() };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = if let Ok(l) = line { l } else { continue; };
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        let local = parse_ipv4_pair(cols[1]);
        let remote = parse_ipv4_pair(cols[2]);
        let state = tcp_state_from_hex(cols[3]);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let pids = inode_to_pids.get(&inode).cloned().unwrap_or_default().into_iter().collect::<Vec<_>>();
        let tmp = SocketEntry {
            proto: proto.to_string(),
            local_addr: local,
            remote_addr: remote,
            state,
            inode,
            pids,
            score: 0,
        };
        entries.push(with_score(tmp));
    }
    entries
}

fn read_tcp6_table(path: &str, proto: &str, inode_to_pids: &HashMap<u64, HashSet<i32>>) -> Vec<SocketEntry> {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return Vec::new() };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = if let Ok(l) = line { l } else { continue; };
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        let local = parse_ipv6_pair(cols[1]);
        let remote = parse_ipv6_pair(cols[2]);
        let state = tcp_state_from_hex(cols[3]);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let pids = inode_to_pids.get(&inode).cloned().unwrap_or_default().into_iter().collect::<Vec<_>>();
        let tmp = SocketEntry {
            proto: proto.to_string(),
            local_addr: local,
            remote_addr: remote,
            state,
            inode,
            pids,
            score: 0,
        };
        entries.push(with_score(tmp));
    }
    entries
}

fn read_udp_table(path: &str, proto: &str, inode_to_pids: &HashMap<u64, HashSet<i32>>) -> Vec<SocketEntry> {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return Vec::new() };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = if let Ok(l) = line { l } else { continue; };
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        let local = parse_ipv4_pair(cols[1]);
        let remote = parse_ipv4_pair(cols[2]);
        let state = format!("0x{}", cols[3]);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let pids = inode_to_pids.get(&inode).cloned().unwrap_or_default().into_iter().collect::<Vec<_>>();
        let tmp = SocketEntry {
            proto: proto.to_string(),
            local_addr: local,
            remote_addr: remote,
            state,
            inode,
            pids,
            score: 0,
        };
        entries.push(with_score(tmp));
    }
    entries
}

fn read_udp6_table(path: &str, proto: &str, inode_to_pids: &HashMap<u64, HashSet<i32>>) -> Vec<SocketEntry> {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return Vec::new() };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = if let Ok(l) = line { l } else { continue; };
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        let local = parse_ipv6_pair(cols[1]);
        let remote = parse_ipv6_pair(cols[2]);
        let state = format!("0x{}", cols[3]);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let pids = inode_to_pids.get(&inode).cloned().unwrap_or_default().into_iter().collect::<Vec<_>>();
        let tmp = SocketEntry {
            proto: proto.to_string(),
            local_addr: local,
            remote_addr: remote,
            state,
            inode,
            pids,
            score: 0,
        };
        entries.push(with_score(tmp));
    }
    entries
}

fn with_score(mut e: SocketEntry) -> SocketEntry {
    e.score = suspicious_score(&e);
    e
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

fn parse_ipv4_pair(hexpair: &str) -> String {
    let mut parts = hexpair.split(':');
    let ip_hex = parts.next().unwrap_or("00000000");
    let port_hex = parts.next().unwrap_or("0000");
    let ip = parse_ipv4_hex(ip_hex);
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    format!("{}:{}", ip, port)
}

fn parse_ipv6_pair(hexpair: &str) -> String {
    let mut parts = hexpair.split(':');
    let ip_hex = parts.next().unwrap_or("");
    let port_hex = parts.next().unwrap_or("0000");
    let ip = parse_ipv6_hex(ip_hex);
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    format!("{}:{}", ip, port)
}

fn parse_ipv4_hex(h: &str) -> Ipv4Addr {
    if h.len() != 8 { return Ipv4Addr::new(0, 0, 0, 0); }
    let b0 = u8::from_str_radix(&h[6..8], 16).unwrap_or(0);
    let b1 = u8::from_str_radix(&h[4..6], 16).unwrap_or(0);
    let b2 = u8::from_str_radix(&h[2..4], 16).unwrap_or(0);
    let b3 = u8::from_str_radix(&h[0..2], 16).unwrap_or(0);
    Ipv4Addr::new(b0, b1, b2, b3)
}

fn parse_ipv6_hex(h: &str) -> Ipv6Addr {
    if h.len() != 32 { return Ipv6Addr::UNSPECIFIED; }
    let mut seg = [0u16; 8];
    for i in 0..8 {
        let start = i * 4;
        let part = &h[start..start + 4];
        let lo = u8::from_str_radix(&part[0..2], 16).unwrap_or(0);
        let hi = u8::from_str_radix(&part[2..4], 16).unwrap_or(0);
        seg[i] = ((hi as u16) << 8) | lo as u16;
    }
    Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7])
}

fn tcp_state_from_hex(h: &str) -> String {
    match h {
        "01" => "ESTABLISHED","02" => "SYN_SENT","03" => "SYN_RECV","04" => "FIN_WAIT1","05" => "FIN_WAIT2",
        "06" => "TIME_WAIT","07" => "CLOSE","08" => "CLOSE_WAIT","09" => "LAST_ACK","0A" => "LISTEN",
        "0B" => "CLOSING","0C" => "NEW_SYN_RECV",_ => "UNKNOWN",
    }.to_string()
}

fn is_private_v4(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") ||
    ip.starts_with("172.16.") || ip.starts_with("172.17.") ||
    ip.starts_with("172.18.") || ip.starts_with("172.19.") || ip.starts_with("172.2")
}

fn suspicious_score(e: &SocketEntry) -> i32 {
    let mut score = 0;
    if e.state == "LISTEN" && (e.local_addr.starts_with("0.0.0.0:") || e.local_addr.starts_with(":::")) { score += 2; }
    if (e.state == "ESTABLISHED" || e.proto.starts_with("udp")) &&
       !(e.remote_addr.starts_with("0.0.0.0:") || e.remote_addr.starts_with("[::]:")) {
        if let Some(ip) = e.remote_addr.split(':').next() {
            if ip.chars().filter(|c| *c == '.').count() == 3 && !is_private_v4(ip) { score += 1; }
        }
    }
    if e.pids.is_empty() { score += 1; }
    score
}
