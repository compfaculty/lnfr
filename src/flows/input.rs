use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    conntrack::NatEvent,
    event::{BridgeEvent, Endpoint, Observation, RouteEvent, TcEvent},
    probes::BRIDGE_FORWARD,
};

const MAX_LINE: usize = 16 * 1024;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;

#[derive(Debug, Deserialize)]
pub(super) struct Event {
    pub monotonic_ns: u64,
    pub netns_inum: Option<u32>,
    pub socket_cookie: Option<u64>,
    pub context_tid: Option<u32>,
    pub local: Option<Endpoint>,
    pub remote: Option<Endpoint>,
    #[serde(flatten)]
    pub observation: Observation,
}

pub(super) struct Evidence {
    pub line: usize,
    pub event: Event,
    pub raw: Value,
}

pub(super) struct NatEvidence {
    pub line: usize,
    pub event: NatEvent,
    pub raw: Value,
}

pub(super) struct TcEvidence {
    pub line: usize,
    pub event: TcEvent,
    pub raw: Value,
}

pub(super) struct BridgeEvidence {
    pub line: usize,
    pub event: BridgeEvent,
    pub raw: Value,
}

pub(super) struct RouteEvidence {
    pub line: usize,
    pub event: RouteEvent,
    pub raw: Value,
}

#[derive(Default)]
pub(super) struct Session {
    pub events: Vec<Evidence>,
    pub nat: Vec<NatEvidence>,
    pub tc: Vec<TcEvidence>,
    pub bridge: Vec<BridgeEvidence>,
    pub routes: Vec<RouteEvidence>,
    pub active_probes: Vec<String>,
    pub gaps: Vec<String>,
    pub blind_spots: Vec<String>,
}

impl Session {
    pub fn read(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open capture {}", path.display()))?;
        Self::parse(BufReader::new(file))
    }

    pub fn parse(reader: impl BufRead) -> Result<Self> {
        Self::parse_window(reader, None)
    }

    pub fn parse_live(reader: impl BufRead, evicted: usize) -> Result<Self> {
        Self::parse_window(reader, Some(evicted))
    }

    fn parse_window(mut reader: impl BufRead, live_evicted: Option<usize>) -> Result<Self> {
        let mut session = Self::default();
        let mut buffer = Vec::new();
        let mut bytes = 0;
        let mut line = 0;
        let mut version = None;
        let mut start = None;
        let mut end = None;
        loop {
            buffer.clear();
            let size = reader
                .by_ref()
                .take((MAX_LINE + 1) as u64)
                .read_until(b'\n', &mut buffer)
                .context("read capture")?;
            if size == 0 {
                break;
            }
            line += 1;
            bytes += size;
            ensure!(
                size <= MAX_LINE,
                "capture line {line} exceeds {MAX_LINE} bytes"
            );
            ensure!(bytes <= MAX_BYTES, "capture exceeds {MAX_BYTES} bytes");
            if buffer.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            let raw: Value = serde_json::from_slice(&buffer)
                .with_context(|| format!("parse capture line {line}"))?;
            let schema = raw["schema_version"].as_u64();
            ensure!(
                matches!(schema, Some(1 | 2)),
                "unsupported schema version at line {line}"
            );
            ensure!(
                version.is_none() || version == schema,
                "mixed schema versions at line {line}"
            );
            version = schema;

            ensure!(
                end.is_none(),
                "unexpected record after capture end at line {line}"
            );
            match raw["record"].as_str() {
                Some("capture_start") => {
                    ensure!(
                        start.is_none() && session.record_count() == 0,
                        "unexpected capture start at line {line}"
                    );
                    start = Some(raw);
                }
                Some("capture_end") => end = Some(raw),
                Some("socket_state" | "tcp_connect" | "tcp_accept" | "tcp_retransmit") => {
                    ensure!(
                        session.record_count() < MAX_EVENTS,
                        "capture exceeds {MAX_EVENTS} events"
                    );
                    let event = Event::deserialize(&raw)
                        .with_context(|| format!("decode event at line {line}"))?;
                    session.events.push(Evidence { line, event, raw });
                }
                Some("conntrack_nat") if schema == Some(2) => {
                    ensure!(
                        session.record_count() < MAX_EVENTS,
                        "capture exceeds {MAX_EVENTS} events"
                    );
                    let event = NatEvent::deserialize(&raw)
                        .with_context(|| format!("decode NAT observation at line {line}"))?;
                    ensure!(
                        event.translated == event.reply.reverse()
                            && event.original != event.translated
                            && (event.source_nat || event.destination_nat),
                        "inconsistent NAT tuple data at line {line}"
                    );
                    session.nat.push(NatEvidence { line, event, raw });
                }
                Some("tc_packet") if schema == Some(2) => {
                    ensure!(
                        session.record_count() < MAX_EVENTS,
                        "capture exceeds {MAX_EVENTS} events"
                    );
                    let event = TcEvent::deserialize(&raw)
                        .with_context(|| format!("decode TC observation at line {line}"))?;
                    ensure!(
                        event.ifindex != 0
                            && event.netns_inum != 0
                            && raw["hook"] == event.direction.hook(),
                        "inconsistent TC metadata at line {line}"
                    );
                    session.tc.push(TcEvidence { line, event, raw });
                }
                Some("bridge_forward") if schema == Some(2) => {
                    ensure!(
                        session.record_count() < MAX_EVENTS,
                        "capture exceeds {MAX_EVENTS} events"
                    );
                    let event = BridgeEvent::deserialize(&raw)
                        .with_context(|| format!("decode bridge observation at line {line}"))?;
                    ensure!(
                        raw["hook"] == BRIDGE_FORWARD
                            && event.netns_inum != 0
                            && event.bridge_ifindex != 0
                            && event.egress_ifindex != 0
                            && event.ingress_ifindex.is_none() == event.local_origin
                            && event.ingress_ifindex != Some(0),
                        "inconsistent bridge metadata at line {line}"
                    );
                    session.bridge.push(BridgeEvidence { line, event, raw });
                }
                Some("route_forward") if schema == Some(2) => {
                    ensure!(
                        session.record_count() < MAX_EVENTS,
                        "capture exceeds {MAX_EVENTS} events"
                    );
                    let event = RouteEvent::deserialize(&raw)
                        .with_context(|| format!("decode routing observation at line {line}"))?;
                    ensure!(
                        event
                            .expected_hook()
                            .is_some_and(|hook| raw["hook"] == hook)
                            && event.netns_inum != 0
                            && event.ingress_ifindex != 0
                            && event.egress_ifindex != 0,
                        "inconsistent routing metadata at line {line}"
                    );
                    session.routes.push(RouteEvidence { line, event, raw });
                }
                _ => bail!("unsupported capture record at line {line}"),
            }
        }
        ensure!(line > 0 && version.is_some(), "capture has no records");
        session.apply_metadata(start, end, live_evicted);
        if let Some(evicted) = live_evicted {
            for item in &mut session.events {
                item.line = item.line.saturating_add(evicted);
            }
            if evicted != 0 {
                session
                    .gaps
                    .push(format!("Live history rotated out {evicted} older events"));
            }
        }
        session
            .routes
            .sort_unstable_by_key(|item| (item.event.monotonic_ns, item.line));
        session
            .bridge
            .sort_unstable_by_key(|item| (item.event.monotonic_ns, item.line));
        session
            .tc
            .sort_unstable_by_key(|item| (item.event.monotonic_ns, item.line));
        session
            .events
            .sort_unstable_by_key(|item| (item.event.monotonic_ns, item.line));
        Ok(session)
    }

    fn record_count(&self) -> usize {
        self.bpf_count() + self.nat.len()
    }

    fn bpf_count(&self) -> usize {
        self.events.len() + self.tc.len() + self.bridge.len() + self.routes.len()
    }

    fn apply_metadata(
        &mut self,
        start: Option<Value>,
        end: Option<Value>,
        live_evicted: Option<usize>,
    ) {
        let conntrack_enabled = start
            .as_ref()
            .is_some_and(|value| value["conntrack_netns_inum"].as_u64().is_some());
        if conntrack_enabled || !self.nat.is_empty() {
            self.blind_spots.push("Conntrack covers the subscription namespace and emits no historical snapshot. Receipt timestamps do not give packet order.".to_owned());
        }
        if start
            .as_ref()
            .is_some_and(|value| value["tc_interface"].is_object())
            || !self.tc.is_empty()
        {
            self.blind_spots.push("TC records cover the selected interface. Offloads and repeated traversal can change skb boundaries; tuple matches cannot identify individual packets.".to_owned());
        }
        if start
            .as_ref()
            .is_some_and(|value| value["bridge_interface"].is_object())
            || !self.bridge.is_empty()
        {
            self.blind_spots.push("Bridge forwarding observations report software port selection and do not identify a socket flow or prove delivery.".to_owned());
        }
        if start
            .as_ref()
            .is_some_and(|value| value["routing_netns_inum"].as_u64().is_some())
            || !self.routes.is_empty()
        {
            self.blind_spots.push("Routing observations cover the attached destination at IP forwarding entry. FIB misses, policy changes, local delivery, and actual output are outside this observation.".to_owned());
        }
        if let Some(start) = start {
            if let Some(blind_spots) = start["blind_spots"].as_array() {
                self.blind_spots.extend(
                    blind_spots
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            }
            if let Some(disabled) = start["disabled_probes"].as_object() {
                for (hook, reason) in disabled {
                    self.gaps.push(format!(
                        "Probe {hook} disabled ({})",
                        reason.as_str().unwrap_or("reason unavailable")
                    ));
                }
            }
            if let Some(active) = start["active_probes"].as_array() {
                self.active_probes
                    .extend(active.iter().filter_map(Value::as_str).map(str::to_owned));
            } else {
                self.gaps.push("Active probe list unavailable".to_owned());
            }
            if start["context_tgid_filter"].as_u64().is_some() {
                self.gaps.push(
                    "Execution-context filtering can omit timer and interrupt events".to_owned(),
                );
            }
            if start["netns_inum_filter"].as_u64().is_some() {
                self.blind_spots
                    .push("Capture covers only the selected socket namespace".to_owned());
            }
        } else {
            self.gaps
                .push("Capture start metadata unavailable".to_owned());
        }

        if let Some(end) = end {
            for (key, label) in [
                ("ring_lost", "ring-buffer loss"),
                ("rate_limited", "rate-limited events"),
                ("connect_tracking_lost", "connect timing entries lost"),
            ] {
                if let Some(number) = end["stats"][key].as_u64().filter(|n| *n > 0) {
                    self.gaps.push(format!("{number} {label}"));
                }
            }
            if end["received"].as_u64()
                != Some(self.bpf_count().saturating_add(live_evicted.unwrap_or(0)) as u64)
                || end["received"] != end["stats"]["submitted"]
            {
                self.gaps
                    .push("Capture event counts are missing or disagree".to_owned());
            }
            if conntrack_enabled || !self.nat.is_empty() {
                let stats = &end["conntrack_stats"];
                if stats["received"].as_u64() != Some(self.nat.len() as u64) {
                    self.gaps
                        .push("Conntrack event counts are missing or disagree".to_owned());
                }
                for (key, label) in [
                    ("overruns", "conntrack overflow notifications"),
                    ("truncated_datagrams", "truncated conntrack datagrams"),
                    ("decode_errors", "conntrack decode errors"),
                    ("rate_limited", "rate-limited conntrack events"),
                ] {
                    match stats[key].as_u64() {
                        Some(0) => {}
                        Some(number) => self.gaps.push(format!("{number} {label}")),
                        None => self.gaps.push(format!("Counter unavailable for {label}")),
                    }
                }
            }
            if end["stats"]["ring_lost"].as_u64().is_none()
                || end["stats"]["rate_limited"].as_u64().is_none()
            {
                self.gaps
                    .push("Capture loss counters unavailable".to_owned());
            }
        } else if live_evicted.is_some() {
            self.blind_spots
                .push("Live capture loss totals are available when capture stops.".to_owned());
        } else {
            self.gaps
                .push("Capture end metadata unavailable".to_owned());
        }
        self.blind_spots.push("Flow timelines cover one capture window and one socket direction. Packet loss location and application delays are outside these observations.".to_owned());
    }
}
