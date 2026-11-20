mod input;

use std::{
    collections::HashMap,
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    conntrack,
    event::{Endpoint, Observation},
};

use self::input::{Event, Evidence, Session};

const SYN_SENT: i32 = 2;
const ESTABLISHED: i32 = 1;
const TIME_WAIT: i32 = 6;
const CLOSE: i32 = 7;
const TUPLE_IDLE_NS: u64 = 120_000_000_000;

#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Tuple {
    pub netns_inum: u32,
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl Tuple {
    fn from_event(event: &Event) -> Option<Self> {
        let local = event.local?;
        let remote = event.remote?;
        Some(Self {
            netns_inum: event.netns_inum.filter(|ns| *ns != 0)?,
            local: usable_endpoint(local)?,
            remote: usable_endpoint(remote)?,
        })
    }
}

fn usable_endpoint(endpoint: Endpoint) -> Option<Endpoint> {
    (endpoint.port.is_some_and(|port| port != 0) && !endpoint.address.is_unspecified())
        .then_some(endpoint)
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct AttemptKey {
    netns_inum: u32,
    tid: u32,
    peer: Endpoint,
}

impl AttemptKey {
    fn new(event: &Event, peer: Endpoint) -> Option<Self> {
        Some(Self {
            netns_inum: event.netns_inum.filter(|ns| *ns != 0)?,
            tid: event.context_tid.filter(|tid| *tid != 0)?,
            peer: usable_endpoint(peer)?,
        })
    }
}

#[derive(Default)]
struct Index {
    cookies: HashMap<(Option<u32>, u64), usize>,
    tuples: HashMap<Tuple, usize>,
    attempts: HashMap<AttemptKey, Vec<(u64, usize)>>,
    flows: Vec<Flow>,
}

#[derive(Default)]
struct Flow {
    evidence: Vec<usize>,
    tuple: Option<Tuple>,
    cookie: Option<u64>,
    heuristic_match: bool,
    terminal: bool,
}

impl Index {
    fn build(events: &[Evidence]) -> Self {
        let mut index = Self::default();
        for (position, item) in events.iter().enumerate() {
            index.add(events, position, &item.event);
        }
        index
    }

    fn add(&mut self, events: &[Evidence], position: usize, event: &Event) {
        let tuple = Tuple::from_event(event);
        let cookie = event.socket_cookie.filter(|value| *value != 0);
        let cookie_key = cookie.map(|value| (event.netns_inum, value));
        let starts = matches!(
            event.observation,
            Observation::SocketState {
                oldstate: CLOSE,
                newstate: SYN_SENT
            }
        );
        let closes = matches!(
            event.observation,
            Observation::SocketState {
                newstate: CLOSE | TIME_WAIT,
                ..
            }
        );

        let by_cookie = cookie_key.and_then(|key| self.cookies.get(&key).copied());
        let by_tuple = tuple
            .and_then(|key| self.tuples.get(&key).copied())
            .filter(|&index| {
                let flow = &self.flows[index];
                let last = &events[*flow.evidence.last().expect("existing flow")].event;
                !starts
                    && (!flow.terminal || closes)
                    && event.monotonic_ns - last.monotonic_ns <= TUPLE_IDLE_NS
                    && (cookie.is_none() || flow.cookie.is_none() || cookie == flow.cookie)
            });
        let by_attempt = (by_tuple.is_none() && by_cookie.is_none())
            .then(|| self.connect_attempt(event))
            .flatten()
            .filter(|&index| {
                let candidate = self.flows[index].cookie;
                cookie.is_none() || candidate.is_none() || cookie == candidate
            });

        let previous = by_cookie.or(by_tuple).or(by_attempt);
        let index = previous.unwrap_or_else(|| {
            self.flows.push(Flow::default());
            self.flows.len() - 1
        });
        let flow = &mut self.flows[index];
        flow.evidence.push(position);
        flow.heuristic_match |= previous.is_some() && by_cookie.is_none();
        flow.cookie = flow.cookie.or(cookie);
        flow.tuple = flow.tuple.or(tuple);
        if starts || closes {
            flow.terminal = closes;
        }
        if let Some(key) = cookie_key {
            self.cookies.insert(key, index);
        }
        if let Some(tuple) = tuple {
            if starts || previous.is_none() || !self.tuples.contains_key(&tuple) {
                self.tuples.insert(tuple, index);
            }
            if starts && let Some(attempt) = AttemptKey::new(event, tuple.remote) {
                self.attempts
                    .entry(attempt)
                    .or_default()
                    .push((event.monotonic_ns, index));
            }
        }
    }

    fn connect_attempt(&self, event: &Event) -> Option<usize> {
        let Observation::TcpConnect {
            requested_peer: Some(peer),
            connect_elapsed_ns: Some(elapsed),
            ..
        } = event.observation
        else {
            return None;
        };
        let key = AttemptKey::new(event, peer)?;
        let candidates = self.attempts.get(&key)?;
        let start = event.monotonic_ns.checked_sub(elapsed.get())?;
        let first = candidates.partition_point(|&(time, _)| time < start);
        let (time, index) = *candidates.get(first)?;
        let unique = candidates
            .get(first + 1)
            .is_none_or(|&(next, _)| next > event.monotonic_ns);
        (time <= event.monotonic_ns && unique).then_some(index)
    }
}

#[derive(Serialize)]
pub(crate) struct FlowSummary {
    pub flow_id: String,
    pub netns_inum: Option<u32>,
    pub tuple: Option<Tuple>,
    pub requested_peer: Option<Endpoint>,
    pub socket_cookie: Option<u64>,
    pub correlation_confidence: &'static str,
    pub event_count: usize,
    pub first_monotonic_ns: u64,
    pub last_monotonic_ns: u64,
}

impl Flow {
    fn items<'a>(&'a self, session: &'a Session) -> impl Iterator<Item = &'a Evidence> {
        self.evidence.iter().map(|&index| &session.events[index])
    }

    fn summarize(&self, session: &Session) -> FlowSummary {
        let first = &session.events[self.evidence[0]];
        let last = &session.events[*self.evidence.last().expect("nonempty flow")];
        FlowSummary {
            flow_id: format!("flow-{}", first.line),
            netns_inum: first.event.netns_inum,
            tuple: self.tuple,
            requested_peer: self
                .items(session)
                .find_map(|item| match item.event.observation {
                    Observation::TcpConnect { requested_peer, .. } => requested_peer,
                    _ => None,
                }),
            socket_cookie: self.cookie,
            correlation_confidence: if self.heuristic_match {
                if session.gaps.is_empty() {
                    "probable"
                } else {
                    "possible"
                }
            } else if self.cookie.is_some() {
                "confirmed"
            } else {
                "unknown"
            },
            event_count: self.evidence.len(),
            first_monotonic_ns: first.event.monotonic_ns,
            last_monotonic_ns: last.event.monotonic_ns,
        }
    }

    fn diagnoses(&self, session: &Session) -> Vec<Diagnosis> {
        let mut diagnoses = Vec::new();
        let mut completion = false;
        for (code, observation, alternatives, predicate) in RULES {
            let evidence_ids = self
                .items(session)
                .filter(|item| predicate(&item.event.observation))
                .map(evidence_id)
                .collect::<Vec<_>>();
            if !evidence_ids.is_empty() {
                completion |= *code != "retransmit_observed";
                diagnoses.push(Diagnosis {
                    code,
                    confidence: "confirmed",
                    observation,
                    alternatives,
                    evidence_ids,
                });
            }
        }
        if !completion {
            let attempts = self
                .items(session)
                .filter(|item| attempt_observed(&item.event.observation))
                .map(evidence_id)
                .collect::<Vec<_>>();
            if attempts.is_empty() {
                diagnoses.push(Diagnosis {
                    code: "insufficient_evidence",
                    confidence: "unknown",
                    observation: "The available events do not establish the connection outcome.",
                    alternatives: &[
                        "The capture may have begun after the connection was established.",
                    ],
                    evidence_ids: self.items(session).map(evidence_id).collect(),
                });
            } else {
                diagnoses.push(Diagnosis {
                    code: "completion_not_observed",
                    confidence: "unknown",
                    observation: "A connection attempt was observed. Its outcome is unknown within this capture.",
                    alternatives: &["The connection may have completed outside the capture window or through an unobserved event."],
                    evidence_ids: attempts,
                });
            }
        }
        diagnoses
    }
}

#[derive(Serialize)]
pub(crate) struct Diagnosis {
    pub code: &'static str,
    pub confidence: &'static str,
    pub observation: &'static str,
    pub alternatives: &'static [&'static str],
    pub evidence_ids: Vec<String>,
}

type Rule = (
    &'static str,
    &'static str,
    &'static [&'static str],
    fn(&Observation) -> bool,
);

const RULES: &[Rule] = &[
    (
        "connection_established",
        "An established state, successful connect return, or accepted TCP socket was observed.",
        &["These observations do not measure application response time."],
        |event| {
            matches!(
                event,
                Observation::SocketState {
                    newstate: ESTABLISHED,
                    ..
                } | Observation::TcpConnect { result: 0, .. }
                    | Observation::TcpAccept
            )
        },
    ),
    (
        "connection_refused",
        "The kernel connect call returned ECONNREFUSED.",
        &["The capture does not identify what generated the refusal."],
        |event| matches!(event, Observation::TcpConnect { result, .. } if *result == -libc::ECONNREFUSED),
    ),
    (
        "connect_timeout",
        "The kernel connect call returned ETIMEDOUT.",
        &["The timeout alone cannot identify a loss location or firewall behavior."],
        |event| matches!(event, Observation::TcpConnect { result, .. } if *result == -libc::ETIMEDOUT),
    ),
    (
        "retransmit_observed",
        "The TCP retransmit hook fired. The timeline includes each hook return code.",
        &[
            "Delay, packet loss, or reordering can lead to retransmits. Their location and cause are unproven.",
        ],
        |event| matches!(event, Observation::TcpRetransmit { .. }),
    ),
];

fn attempt_observed(event: &Observation) -> bool {
    matches!(
        event,
        Observation::SocketState {
            newstate: SYN_SENT,
            ..
        }
    ) || matches!(event, Observation::TcpConnect { result, .. }
            if *result == -libc::EINPROGRESS || *result == -libc::EALREADY)
}

fn evidence_id(item: &Evidence) -> String {
    format!("line-{}", item.line)
}

#[derive(Serialize)]
pub(crate) struct TimelineItem<'a> {
    pub evidence_id: String,
    pub event: &'a serde_json::Value,
}

#[derive(Serialize)]
pub(crate) struct Explanation<'a> {
    #[serde(flatten)]
    pub flow: FlowSummary,
    pub diagnoses: Vec<Diagnosis>,
    pub capture_gaps: &'a [String],
    pub blind_spots: &'a [String],
    pub timeline: Vec<TimelineItem<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat_association: Option<NatAssociation<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat_association_note: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tc_observations: Vec<TimelineItem<'a>>,
}

const NAT_RECEIPT_TOLERANCE_NS: u64 = 1_000_000_000;

#[derive(Serialize)]
pub(crate) struct NatAssociation<'a> {
    pub side: &'static str,
    pub confidence: &'static str,
    pub translation_confidence: &'static str,
    pub evidence: TimelineItem<'a>,
}

fn near_flow(item: &input::NatEvidence, flow: &Flow, session: &Session) -> bool {
    let first = session.events[flow.evidence[0]].event.monotonic_ns;
    let last = session.events[*flow.evidence.last().expect("nonempty flow")]
        .event
        .monotonic_ns;
    let received = item.event.receipt_monotonic_ns;
    received >= first.saturating_sub(NAT_RECEIPT_TOLERANCE_NS)
        && received <= last.saturating_add(NAT_RECEIPT_TOLERANCE_NS)
}

fn associate_nat<'a>(
    flow: &Flow,
    flows: &[Flow],
    session: &'a Session,
) -> (Option<NatAssociation<'a>>, Option<&'static str>) {
    let Some(tuple) = flow.tuple else {
        return (None, None);
    };
    let pair = conntrack::Tuple {
        src: tuple.local,
        dst: tuple.remote,
    };
    let mut candidates = session
        .nat
        .iter()
        .filter(|item| item.event.is_new() && near_flow(item, flow, session))
        .flat_map(|item| {
            [
                (item.event.original, "original"),
                (item.event.original.reverse(), "original_reverse"),
                (item.event.translated, "translated"),
                (item.event.reply, "translated_reverse"),
            ]
            .into_iter()
            .filter(move |(key, _)| *key == pair)
            .map(move |(_, side)| (item, side))
        });
    let Some((item, side)) = candidates.next() else {
        return (None, None);
    };
    let competing_flow = flows
        .iter()
        .filter(|other| {
            other
                .tuple
                .is_some_and(|key| key.local == tuple.local && key.remote == tuple.remote)
                && near_flow(item, other, session)
        })
        .take(2)
        .count()
        > 1;
    if candidates.next().is_some() || competing_flow {
        return (
            None,
            Some(
                "Multiple conntrack observations or socket flows match this tuple and time window.",
            ),
        );
    }

    (
        Some(NatAssociation {
            side,
            confidence: "possible",
            translation_confidence: "confirmed",
            evidence: TimelineItem {
                evidence_id: format!("line-{}", item.line),
                event: &item.raw,
            },
        }),
        None,
    )
}

const TC_WINDOW_MARGIN_NS: u64 = 250_000_000;

fn tc_observations<'a>(flow: &Flow, flows: &[Flow], session: &'a Session) -> Vec<TimelineItem<'a>> {
    let Some(tuple) = flow.tuple else {
        return Vec::new();
    };
    let window = |flow: &Flow| {
        let first = session.events[flow.evidence[0]].event.monotonic_ns;
        let last = session.events[*flow.evidence.last().expect("nonempty flow")]
            .event
            .monotonic_ns;
        (
            first.saturating_sub(TC_WINDOW_MARGIN_NS),
            last.saturating_add(TC_WINDOW_MARGIN_NS),
        )
    };
    let (start, end) = window(flow);
    let mut competing = flows
        .iter()
        .filter(|other| other.tuple == Some(tuple))
        .map(window)
        .filter(|&(other_start, other_end)| other_start <= end && other_end >= start);
    if competing.nth(1).is_some() {
        return Vec::new();
    }
    let first = session
        .tc
        .partition_point(|item| item.event.monotonic_ns < start);
    session.tc[first..]
        .iter()
        .take_while(|item| item.event.monotonic_ns <= end)
        .filter(|item| {
            let event = &item.event;
            event.netns_inum == tuple.netns_inum
                && match event.direction {
                    crate::tc::Direction::Ingress => {
                        event.src == tuple.remote && event.dst == tuple.local
                    }
                    crate::tc::Direction::Egress => {
                        event.src == tuple.local && event.dst == tuple.remote
                    }
                }
        })
        .map(|item| TimelineItem {
            evidence_id: format!("line-{}", item.line),
            event: &item.raw,
        })
        .collect()
}

pub fn report_nat(path: &Path) -> Result<()> {
    let session = Session::read(path)?;
    write_path_observations(session.nat.iter().map(|item| (item.line, &item.raw)))
}

pub fn report_tc(path: &Path) -> Result<()> {
    let session = Session::read(path)?;
    write_path_observations(session.tc.iter().map(|item| (item.line, &item.raw)))
}

pub fn report_bridge(path: &Path) -> Result<()> {
    let session = Session::read(path)?;
    write_path_observations(session.bridge.iter().map(|item| (item.line, &item.raw)))
}

pub fn report_routes(path: &Path) -> Result<()> {
    let session = Session::read(path)?;
    write_path_observations(session.routes.iter().map(|item| (item.line, &item.raw)))
}

fn write_path_observations<'a>(
    items: impl Iterator<Item = (usize, &'a serde_json::Value)>,
) -> Result<()> {
    let mut output = io::stdout().lock();
    for (line, event) in items {
        serde_json::to_writer(
            &mut output,
            &TimelineItem {
                evidence_id: format!("line-{line}"),
                event,
            },
        )?;
        writeln!(output)?;
    }
    output.flush().context("flush path observations")
}

pub(crate) struct Review {
    session: Session,
    flows: Vec<Flow>,
}

impl Review {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self::from_session(Session::read(path)?))
    }

    pub(crate) fn from_live_window(input: &[u8], evicted: usize) -> Result<Self> {
        let session = if input.is_empty() {
            Session::default()
        } else {
            Session::parse_live(input, evicted)?
        };
        Ok(Self::from_session(session))
    }

    #[cfg(test)]
    pub(crate) fn from_jsonl(input: &[u8]) -> Result<Self> {
        Ok(Self::from_session(Session::parse(input)?))
    }

    fn from_session(session: Session) -> Self {
        let flows = Index::build(&session.events).flows;
        Self { session, flows }
    }

    pub fn summaries(&self) -> impl Iterator<Item = FlowSummary> {
        self.flows.iter().map(|flow| flow.summarize(&self.session))
    }

    pub fn active_probes(&self) -> &[String] {
        &self.session.active_probes
    }
    pub fn capture_gaps(&self) -> &[String] {
        &self.session.gaps
    }
    pub fn blind_spots(&self) -> &[String] {
        &self.session.blind_spots
    }

    pub fn explanation(&self, index: usize) -> Option<Explanation<'_>> {
        let flow = self.flows.get(index)?;
        let session = &self.session;
        let (nat_association, nat_association_note) = associate_nat(flow, &self.flows, session);
        Some(Explanation {
            flow: flow.summarize(session),
            diagnoses: flow.diagnoses(session),
            capture_gaps: self.capture_gaps(),
            blind_spots: self.blind_spots(),
            nat_association,
            nat_association_note,
            tc_observations: tc_observations(flow, &self.flows, session),
            timeline: flow
                .items(session)
                .map(|item| TimelineItem {
                    evidence_id: evidence_id(item),
                    event: &item.raw,
                })
                .collect(),
        })
    }
}

pub fn report(path: &Path, selected: Option<&str>) -> Result<()> {
    let review = Review::load(path)?;
    let mut output = io::stdout().lock();
    if let Some(id) = selected {
        let index = review
            .summaries()
            .position(|flow| flow.flow_id == id)
            .with_context(|| format!("flow {id} not found; run lnfr flows on the same capture"))?;
        serde_json::to_writer_pretty(&mut output, &review.explanation(index))?;
        writeln!(output)?;
    } else {
        for flow in review.summaries() {
            serde_json::to_writer(&mut output, &flow)?;
            writeln!(output)?;
        }
    }
    output.flush().context("flush flow report")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn event(time: u64, record: &str, fields: Value) -> Value {
        let mut event = json!({
            "record": record,
            "schema_version": 2,
            "monotonic_ns": time,
            "netns_inum": 11,
            "context_tid": 90,
            "local": {"address": "192.0.2.1", "port": 50000},
            "remote": {"address": "192.0.2.2", "port": 8080},
        });
        event
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        event
    }

    fn session(events: &[Value], lost: u64) -> Session {
        let start = json!({
            "record": "capture_start", "schema_version": 2,
            "active_probes": ["sock:inet_sock_set_state"],
            "disabled_probes": {},
        });
        let end = json!({
            "record": "capture_end", "schema_version": 2, "received": events.len(),
            "stats": {"submitted": events.len(), "ring_lost": lost, "rate_limited": 0},
        });
        let text = std::iter::once(&start)
            .chain(events)
            .chain(std::iter::once(&end))
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        Session::parse(text.as_bytes()).unwrap()
    }

    fn start(time: u64) -> Value {
        event(
            time,
            "socket_state",
            json!({"oldstate": CLOSE, "newstate": SYN_SENT}),
        )
    }

    #[test]
    fn sorts_and_cites_observed_establishment_without_claiming_loss() {
        let input = session(
            &[
                event(30, "tcp_connect", json!({"result": 0})),
                start(10),
                event(
                    20,
                    "tcp_retransmit",
                    json!({"socket_state": SYN_SENT, "result": 0}),
                ),
            ],
            2,
        );
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 1);
        let flow = &index.flows[0];
        let summary = flow.summarize(&input);
        assert_eq!(summary.flow_id, "flow-3");
        assert_eq!(summary.correlation_confidence, "possible");
        assert_eq!(
            flow.items(&input).map(evidence_id).collect::<Vec<_>>(),
            ["line-3", "line-4", "line-2"]
        );
        let diagnoses = flow.diagnoses(&input);
        assert_eq!(diagnoses[0].code, "connection_established");
        assert_eq!(diagnoses[0].evidence_ids, ["line-2"]);
        assert_eq!(diagnoses[1].code, "retransmit_observed");
        assert_eq!(diagnoses[1].evidence_ids, ["line-4"]);
        assert_eq!(
            diagnoses[1].alternatives[0],
            "Delay, packet loss, or reordering can lead to retransmits. Their location and cause are unproven."
        );
        assert_eq!(input.gaps, ["2 ring-buffer loss"]);
    }

    #[test]
    fn links_refusal_with_missing_ports_only_inside_a_unique_connect_window() {
        let refusal = event(
            30,
            "tcp_connect",
            json!({
                "result": -libc::ECONNREFUSED,
                "connect_elapsed_ns": 20,
                "local": {"address": "192.0.2.1", "port": null},
                "remote": {"address": "192.0.2.2", "port": null},
                "requested_peer": {"address": "192.0.2.2", "port": 8080},
            }),
        );
        let input = session(&[start(12), refusal.clone()], 0);
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 1);
        assert_eq!(
            index.flows[0].diagnoses(&input)[0].code,
            "connection_refused"
        );
        assert_eq!(index.flows[0].diagnoses(&input)[0].evidence_ids, ["line-3"]);

        let mut other = start(14);
        other["local"]["port"] = json!(50001);
        let input = session(&[start(12), other, refusal], 0);
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 3);
        assert_eq!(
            index.flows[2].diagnoses(&input)[0].code,
            "connection_refused"
        );
        assert_eq!(
            index.flows[2].summarize(&input).correlation_confidence,
            "unknown"
        );
    }

    #[test]
    fn separates_namespace_and_new_connect_generations_and_prefers_known_cookie() {
        let mut another_namespace = start(20);
        another_namespace["netns_inum"] = json!(12);
        let input = session(
            &[
                start(10),
                another_namespace,
                start(30),
                event(40, "tcp_connect", json!({"result": 0, "socket_cookie": 42})),
                event(
                    50,
                    "tcp_retransmit",
                    json!({"socket_state": 1, "result": 0, "socket_cookie": 42,
                "local": null, "remote": null}),
                ),
            ],
            0,
        );
        let index = Index::build(&input.events);
        assert_eq!(
            index
                .flows
                .iter()
                .map(|f| f.evidence.len())
                .collect::<Vec<_>>(),
            [1, 1, 3]
        );
        assert_eq!(index.flows[2].cookie, Some(42));
    }

    #[test]
    fn distinguishes_observed_timeout_from_incomplete_and_retransmit_only_captures() {
        let timeout = event(20, "tcp_connect", json!({"result": -libc::ETIMEDOUT}));
        let input = session(&[start(10), timeout], 0);
        let index = Index::build(&input.events);
        assert_eq!(index.flows[0].diagnoses(&input)[0].code, "connect_timeout");

        let input = session(&[start(10)], 0);
        let index = Index::build(&input.events);
        let diagnoses = index.flows[0].diagnoses(&input);
        assert_eq!(diagnoses[0].code, "completion_not_observed");
        assert_eq!(diagnoses[0].confidence, "unknown");

        let input = session(
            &[event(
                10,
                "tcp_retransmit",
                json!({"socket_state": 1, "result": 0}),
            )],
            0,
        );
        let index = Index::build(&input.events);
        let diagnoses = index.flows[0].diagnoses(&input);
        assert_eq!(diagnoses[0].code, "retransmit_observed");
        assert_eq!(diagnoses[1].code, "insufficient_evidence");
    }

    #[test]
    fn annotates_only_unique_nat_matches_without_merging_socket_flows() {
        let tcp = event(10, "tcp_connect", json!({"result": 0}));
        let orig = json!({"src": tcp["local"], "dst": tcp["remote"]});
        let reply = json!({
            "src": {"address": "198.51.100.2", "port": 8888},
            "dst": {"address": "198.51.100.1", "port": 40000}
        });
        let peer = event(
            20,
            "tcp_accept",
            json!({
                "netns_inum": 12, "local": reply["src"], "remote": reply["dst"],
            }),
        );
        let nat = json!({
            "schema_version": 2, "record": "conntrack_nat", "hook": "ctnetlink:conntrack",
            "receipt_monotonic_ns": 30, "conntrack_netns_inum": 77, "conntrack_id": 45,
            "notice": "new", "original_zone": 0, "reply_zone": 0, "original": orig,
            "reply": reply, "translated": {"src": reply["dst"], "dst": reply["src"]},
            "source_nat": true, "destination_nat": true
        });
        let source = format!("{tcp}\n{peer}\n{nat}");
        let input = Session::parse(source.as_bytes()).unwrap();
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 2);
        for (flow, side) in index.flows.iter().zip(["original", "translated_reverse"]) {
            let (association, note) = associate_nat(flow, &index.flows, &input);
            let association = association.unwrap();
            assert!(note.is_none());
            assert_eq!(association.side, side);
            assert_eq!(association.confidence, "possible");
            assert_eq!(association.evidence.evidence_id, "line-3");
        }
        let mut conflicting = nat;
        conflicting["conntrack_id"] = json!(46);
        let input = Session::parse(format!("{source}\n{conflicting}").as_bytes()).unwrap();
        let index = Index::build(&input.events);
        let (association, note) = associate_nat(&index.flows[0], &index.flows, &input);
        assert!(association.is_none());
        assert!(note.is_some());
    }

    #[test]
    fn relates_tc_by_socket_direction_namespace_and_time() {
        let tcp = event(20, "tcp_connect", json!({"result": 0}));
        let egress = json!({
            "record": "tc_packet", "schema_version": 2, "hook": "tcx/egress",
            "direction": "egress", "monotonic_ns": 10, "cpu": 0, "ifindex": 6,
            "netns_inum": 11, "src": tcp["local"], "dst": tcp["remote"],
            "skb_len": 74, "tcp_flags": 2,
        });
        let ingress = json!({
            "record": "tc_packet", "schema_version": 2, "hook": "tcx/ingress",
            "direction": "ingress", "monotonic_ns": 15, "cpu": 0, "ifindex": 6,
            "netns_inum": 11, "src": tcp["remote"], "dst": tcp["local"],
            "skb_len": 74, "tcp_flags": 18,
        });
        let mut foreign = ingress.clone();
        foreign["netns_inum"] = json!(12);
        let mut late = egress.clone();
        late["monotonic_ns"] = json!(500_000_000);
        let source = format!("{tcp}\n{ingress}\n{egress}\n{foreign}\n{late}");
        let input = Session::parse(source.as_bytes()).unwrap();
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 1);
        let observations = tc_observations(&index.flows[0], &index.flows, &input);
        assert_eq!(
            observations
                .iter()
                .map(|item| item.evidence_id.as_str())
                .collect::<Vec<_>>(),
            ["line-3", "line-2"]
        );
        assert_eq!(index.flows[0].diagnoses(&input)[0].evidence_ids, ["line-1"]);

        let reuse = start(30);
        let input = Session::parse(format!("{source}\n{reuse}").as_bytes()).unwrap();
        let index = Index::build(&input.events);
        assert_eq!(index.flows.len(), 2);
        assert!(tc_observations(&index.flows[0], &index.flows, &input).is_empty());
    }

    #[test]
    fn bridge_evidence_counts_as_bpf_records_and_stays_separate_from_socket_flows() {
        let tcp = event(20, "tcp_connect", json!({"result": 0}));
        let bridge = json!({
            "record": "bridge_forward", "schema_version": 2, "hook": "fentry/__br_forward",
            "monotonic_ns": 14, "cpu": 0, "netns_inum": 33, "bridge_ifindex": 10,
            "ingress_ifindex": 11, "egress_ifindex": 12, "local_origin": false, "ether_type": 2048,
            "src_mac": "02:00:00:00:00:11", "dst_mac": "02:00:00:00:00:22", "skb_len": 60
        });
        let start = json!({"record":"capture_start", "schema_version": 2, "active_probes": [
            "sock:inet_sock_set_state", "fentry/__br_forward"
        ]});
        let end = json!({"record":"capture_end", "schema_version": 2, "received": 2, "stats": {
            "submitted": 2, "ring_lost": 0, "rate_limited": 0
        }});
        let input = Session::parse(format!("{start}\n{bridge}\n{tcp}\n{end}").as_bytes()).unwrap();
        assert_eq!(input.bridge[0].line, 2);
        assert_eq!(input.bridge[0].raw, bridge);
        assert!(input.gaps.is_empty());
        let index = Index::build(&input.events);
        assert_eq!(index.flows[0].diagnoses(&input)[0].evidence_ids, ["line-3"]);

        let mut invalid = bridge;
        invalid["ingress_ifindex"] = serde_json::Value::Null;
        assert!(Session::parse(invalid.to_string().as_bytes()).is_err());
    }

    #[test]
    fn routing_observations_are_evidence_without_creating_socket_flows() {
        let tcp = event(20, "tcp_connect", json!({"result": 0}));
        let forward = json!({
            "record": "route_forward", "schema_version": 2, "hook": "fentry/ip_forward",
            "monotonic_ns": 18, "cpu": 0, "netns_inum": 33, "ingress_ifindex": 11,
            "egress_ifindex": 12, "ip_version": 4, "src": "192.0.2.1", "dst": "192.0.2.2",
            "hop_limit": 48, "ip_next_header": 6, "skb_len": 60,
        });
        let end = json!({"record":"capture_end", "schema_version": 2, "received": 2, "stats": {
            "submitted": 2, "ring_lost": 0, "rate_limited": 0
        }});
        let input = Session::parse(format!("{forward}\n{tcp}\n{end}").as_bytes()).unwrap();
        assert_eq!(input.routes[0].line, 1);
        assert_eq!(input.routes[0].raw, forward);
        assert_eq!(input.gaps, ["Capture start metadata unavailable"]);
        assert_eq!(Index::build(&input.events).flows.len(), 1);
        assert!(
            input
                .blind_spots
                .iter()
                .any(|limit| limit.contains("FIB misses"))
        );

        let mut invalid = forward;
        invalid["hook"] = json!("fentry/ip6_forward");
        assert!(Session::parse(invalid.to_string().as_bytes()).is_err());
    }

    #[test]
    fn reads_legacy_states_and_flags_incomplete_metadata() {
        let raw = br#"{"record":"socket_state","schema_version":1,"monotonic_ns":23,"oldstate":7,"newstate":2}"#;
        let session = Session::parse(&raw[..]).unwrap();
        let index = Index::build(&session.events);
        assert_eq!(session.gaps.len(), 2);
        assert_eq!(
            index.flows[0].summarize(&session).correlation_confidence,
            "unknown"
        );
        assert_eq!(
            index.flows[0].diagnoses(&session)[0].code,
            "completion_not_observed"
        );
        assert!(
            Session::parse(&b"{"[..])
                .err()
                .unwrap()
                .to_string()
                .contains("line 1")
        );
    }
}
