# proc_scanner

A Rust-based offensive security tool for enumerating and analyzing Linux `/proc` information.  
Designed for post-exploitation and penetration testing scenarios, it automates the collection of process secrets, suspicious sockets, privilege anomalies, and cross-checks between file descriptors and capabilities.

---

## Features

- **Network Scanner**
  - Parses `/proc/net/{tcp,tcp6,udp,udp6}`
  - Maps socket inodes to owning PIDs
  - Scores suspicious sockets (e.g., `0.0.0.0:LISTEN`, external ESTABLISHED sessions, orphaned sockets)

- **Privilege Scanner**
  - Reads `/proc/[pid]/status`
  - Detects processes with dangerous capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, etc.)
  - Flags non-root processes holding high-privilege capabilities

- **Cross Privilege + FD Scanner**
  - Correlates processes with elevated capabilities and active file descriptors/sockets
  - Highlights potential privilege escalation or lateral movement opportunities

- **Secrets Scanner**
  - Extracts `cmdline` and `environ` from `/proc/[pid]`
  - Searches for sensitive patterns (passwords, API keys, tokens, database credentials)

- **JSON Output**
  - All results are aggregated into a structured JSON report
  - Easy integration with `jq`, SIEMs, or custom tooling

---

## Example Usage

```bash
cargo run > report.json
jq . report.json
