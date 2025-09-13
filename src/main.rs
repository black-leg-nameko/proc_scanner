mod modules;

use modules::{process, network, privilege, fd, report};

fn main() {
    let network = network::collect_network();
    let privileges = privilege::collect_priv_issues();
    let cross = fd::collect_cross_issues();
    let secrets = process::collect_secrets();
    let out = report::Report { network, privileges, cross, secrets };
    println!("{}", report::to_json(&out));
}
