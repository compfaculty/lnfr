mod capture;
mod conntrack;
mod event;
mod flows;
mod netns;
mod probes;
mod tc;
mod tui;

use std::{path::PathBuf, process::ExitCode, time::Duration};

use anyhow::Result;
use clap::{ArgGroup, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Linux Network Flight Recorder")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report tracepoint and BTF availability
    Doctor,
    /// Browse live TCP events or a saved capture
    #[command(group(ArgGroup::new("source").required(true).args(["input", "live"])))]
    Tui {
        /// Open a saved JSONL capture
        #[arg(long)]
        input: Option<PathBuf>,
        /// Start a live TCP capture
        #[arg(long)]
        live: bool,
        /// Restrict live TCP capture to this socket namespace inode
        #[arg(long, requires = "live", value_parser = clap::value_parser!(u32).range(1..))]
        netns_inum: Option<u32>,
        /// Print the collector's final JSON summary after exiting the live UI
        #[arg(long, requires = "live")]
        summary: bool,
    },
    /// List correlated flows from a saved capture
    Flows {
        #[arg(long)]
        input: PathBuf,
    },
    /// List NAT observations from a saved capture
    Nat {
        #[arg(long)]
        input: PathBuf,
    },
    /// List IP forwarding route observations from a saved capture
    Routes {
        #[arg(long)]
        input: PathBuf,
    },
    /// List bridge forwarding observations from a saved capture
    Bridge {
        #[arg(long)]
        input: PathBuf,
    },
    /// List TC packet observations from a saved capture
    Tc {
        #[arg(long)]
        input: PathBuf,
    },
    /// Show a flow's timeline, diagnoses, and supporting evidence
    Explain {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        flow: String,
    },
    /// Write a bounded TCP lifecycle capture as JSONL to stdout
    Capture {
        /// Capture duration in seconds, optionally suffixed with s
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        duration: Duration,
        #[arg(long, hide = true)]
        stop_on_stdin_eof: bool,
        /// Filter by the tracepoint's execution-context thread-group ID
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        tgid: Option<u32>,
        /// Filter by the socket network namespace inode (e.g. stat -Lc %i /proc/PID/ns/net)
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        netns_inum: Option<u32>,
        /// Enable only the socket-state tracepoint
        #[arg(long)]
        state_only: bool,
        /// Subscribe to TCP NAT events in this process's network namespace
        #[arg(long, conflicts_with = "tgid")]
        conntrack: bool,
        /// Attach passive TCX probes to an interface in this process's network namespace
        #[arg(long, conflicts_with = "tgid")]
        tc_interface: Option<String>,
        /// Observe software forwarding on a bridge in this process's network namespace
        #[arg(long, conflicts_with = "tgid")]
        bridge_interface: Option<String>,
        /// Observe IP forwarding in this process's network namespace
        #[arg(long, conflicts_with = "tgid")]
        routing: bool,
    },
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let seconds = value.strip_suffix('s').unwrap_or(value).parse::<u64>();
    match seconds {
        Ok(seconds @ 1..=300) => Ok(Duration::from_secs(seconds)),
        _ => Err("expected a duration between 1s and 300s".into()),
    }
}

fn main() -> ExitCode {
    let result: Result<()> = match Cli::parse().command {
        Command::Doctor => {
            probes::Features::detect().print();
            Ok(())
        }
        Command::Flows { input } => flows::report(&input, None),
        Command::Tui {
            input: Some(input), ..
        } => tui::run(&input),
        Command::Tui {
            live: true,
            netns_inum,
            summary,
            ..
        } => tui::run_live(netns_inum, summary),
        Command::Tui { .. } => unreachable!("clap requires a capture source"),
        Command::Nat { input } => flows::report_nat(&input),
        Command::Tc { input } => flows::report_tc(&input),
        Command::Bridge { input } => flows::report_bridge(&input),
        Command::Routes { input } => flows::report_routes(&input),
        Command::Explain { input, flow } => flows::report(&input, Some(&flow)),
        Command::Capture {
            duration,
            stop_on_stdin_eof,
            tgid,
            netns_inum,
            state_only,
            conntrack,
            tc_interface,
            bridge_interface,
            routing,
        } => capture::run(capture::Options {
            duration: (!stop_on_stdin_eof).then_some(duration),
            tgid,
            netns_inum,
            state_only,
            subscribe_conntrack: conntrack,
            tc_interface: tc_interface.as_deref(),
            bridge_interface: bridge_interface.as_deref(),
            routing,
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lnfr: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_is_bounded() {
        assert_eq!(parse_duration("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_duration("300"), Ok(Duration::from_secs(300)));
        for value in ["", "0s", "301", "-1", "10ms"] {
            assert!(parse_duration(value).is_err());
        }
    }
}
