//! Build a node heartbeat report and print it as pretty JSON.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p parton --example heartbeat_report -- my-node-id my-cell-id
//! ```

// Examples are user-facing CLIs; writing results to stdout is the intended behavior.
#![allow(clippy::print_stdout)]

use parton::build_heartbeat_report;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let node_id = args.next().unwrap_or_else(|| "example-node".to_string());
    let cell_id = args.next().unwrap_or_else(|| "local-default".to_string());

    let report = build_heartbeat_report(&node_id, &cell_id)?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    println!(
        "-- collected {} container(s); {} running",
        report.containers.containers.len(),
        report.containers.summary.running
    );
    Ok(())
}
