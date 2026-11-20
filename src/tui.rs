mod live;

use std::{
    cmp::Reverse,
    io::{self, IsTerminal},
    ops::Range,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Table, TableState,
    },
};
use serde_json::Value;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};

use crate::{
    event::Endpoint,
    flows::{Explanation, FlowSummary, Review},
};

const TEXT: Color = Color::Rgb(220, 229, 237);
const BACKGROUND: Color = Color::Rgb(14, 23, 33);
const DIM: Color = Color::Rgb(144, 164, 181);
const BORDER: Color = Color::Rgb(85, 111, 130);
const ACCENT: Color = Color::Rgb(91, 221, 194);
const WARNING: Color = Color::Rgb(255, 195, 103);
const SELECTED: Color = Color::Rgb(31, 69, 79);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Focus {
    Flows,
    Timeline,
    Details,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Details {
    Event,
    Diagnoses,
    Coverage,
}

#[derive(Default)]
struct Cursor {
    selected: usize,
    offset: usize,
}

impl Cursor {
    fn move_by(&mut self, delta: isize, total: usize) {
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(total.saturating_sub(1));
    }

    fn visible(&mut self, total: usize, height: usize) -> Range<usize> {
        let height = height.max(1);
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset.saturating_add(height) {
            self.offset = self.selected + 1 - height;
        }
        self.offset = self.offset.min(total.saturating_sub(height));
        self.offset..self.offset.saturating_add(height).min(total)
    }
}

struct EvidenceRow<'a> {
    id: String,
    stamp: u64,
    label: String,
    raw: &'a Value,
}

struct LiveView {
    flow_id: Option<String>,
    evidence_id: Option<String>,
    flow_position: usize,
    focus: Focus,
    details: Details,
    scroll: (usize, usize),
    follow: bool,
}

struct App<'a> {
    review: &'a Review,
    filename: String,
    flows: Vec<(usize, FlowSummary)>,
    is_live: bool,
    follow: bool,
    flow: Cursor,
    evidence: Cursor,
    timeline: Vec<EvidenceRow<'a>>,
    explanation: Option<Explanation<'a>>,
    focus: Focus,
    details: Details,
    detail_lines: Vec<String>,
    detail_scroll: (usize, usize),
    detail_height: usize,
}

impl<'a> App<'a> {
    fn new(review: &'a Review, path: &Path) -> Self {
        let filename = clean(
            &path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy(),
        );
        Self::for_source(review, filename, false, None)
    }

    fn for_source(
        review: &'a Review,
        filename: String,
        is_live: bool,
        previous: Option<LiveView>,
    ) -> Self {
        let mut flows: Vec<_> = review.summaries().enumerate().collect();
        if is_live {
            flows.sort_by_key(|(_, summary)| Reverse(summary.last_monotonic_ns));
        }
        let mut app = Self {
            review,
            filename,
            flows,
            is_live,
            follow: is_live,
            flow: Cursor::default(),
            evidence: Cursor::default(),
            timeline: Vec::new(),
            explanation: None,
            focus: Focus::Flows,
            details: Details::Event,
            detail_lines: Vec::new(),
            detail_scroll: (0, 0),
            detail_height: 1,
        };
        if let Some(view) = &previous {
            app.follow = view.follow;
            app.focus = view.focus;
            app.details = view.details;
            if !app.follow {
                let position = app
                    .flows
                    .iter()
                    .position(|(_, flow)| Some(flow.flow_id.as_str()) == view.flow_id.as_deref());
                app.flow.selected = position
                    .unwrap_or_else(|| view.flow_position.min(app.flows.len().saturating_sub(1)));
            }
        }
        app.load_flow();
        if let Some(view) = previous.filter(|view| !view.follow) {
            let evidence = app
                .timeline
                .iter()
                .position(|row| Some(row.id.as_str()) == view.evidence_id.as_deref());
            if let Some(position) = evidence {
                app.evidence.selected = position;
                app.refresh_details();
                app.detail_scroll = view.scroll;
            } else if app.details != Details::Event {
                app.detail_scroll = view.scroll;
            }
        }
        app
    }

    fn live_view(&self) -> LiveView {
        LiveView {
            flow_id: self
                .flows
                .get(self.flow.selected)
                .map(|(_, flow)| flow.flow_id.clone()),
            evidence_id: self
                .timeline
                .get(self.evidence.selected)
                .map(|item| item.id.clone()),
            flow_position: self.flow.selected,
            focus: self.focus,
            details: self.details,
            scroll: self.detail_scroll,
            follow: self.follow,
        }
    }

    fn load_flow(&mut self) {
        self.explanation = self
            .flows
            .get(self.flow.selected)
            .and_then(|(index, _)| self.review.explanation(*index));
        self.timeline.clear();
        if let Some(explanation) = &self.explanation {
            let socket_and_tc = explanation
                .timeline
                .iter()
                .chain(&explanation.tc_observations);
            let nat = explanation
                .nat_association
                .iter()
                .map(|association| &association.evidence);
            self.timeline
                .extend(socket_and_tc.chain(nat).filter_map(|item| {
                    let raw = item.event;
                    let stamp = raw["monotonic_ns"]
                        .as_u64()
                        .or_else(|| raw["receipt_monotonic_ns"].as_u64())?;
                    let id = item.evidence_id.clone();
                    Some(EvidenceRow {
                        label: event_label(raw),
                        id,
                        stamp,
                        raw,
                    })
                }));
            self.timeline.sort_unstable_by_key(|row| {
                let line = row
                    .id
                    .strip_prefix("line-")
                    .and_then(|line| line.parse::<usize>().ok());
                (row.stamp, line)
            });
        }
        self.evidence = Cursor::default();
        if self.follow {
            self.evidence.selected = self.timeline.len().saturating_sub(1);
        }
        self.refresh_details();
    }

    fn refresh_details(&mut self) {
        self.detail_scroll = (0, 0);
        self.detail_lines = match self.details {
            Details::Event => self.timeline.get(self.evidence.selected).map_or_else(
                || vec!["No evidence selected.".to_owned()],
                |row| {
                    let mut lines = vec![
                        row.label.clone(),
                        format!(
                            "Hook  {}",
                            row.raw["hook"]
                                .as_str()
                                .map(clean)
                                .unwrap_or_else(|| "unavailable".into())
                        ),
                        format!(
                            "Time  {} ns{}",
                            row.stamp,
                            if row.raw["receipt_monotonic_ns"].is_u64() {
                                " (receipt)"
                            } else {
                                ""
                            }
                        ),
                        String::new(),
                    ];
                    let json = serde_json::to_string_pretty(row.raw)
                        .expect("a JSON value can be serialized");
                    lines.extend(json.lines().map(clean));
                    lines
                },
            ),
            Details::Diagnoses => self.diagnosis_lines(),
            Details::Coverage => self.coverage_lines(),
        };
    }

    fn diagnosis_lines(&self) -> Vec<String> {
        let Some(explanation) = &self.explanation else {
            return vec!["No flow selected.".to_owned()];
        };
        let flow = &explanation.flow;
        let (local, peer) = endpoints(flow);
        let mut lines = vec![
            format!("{}  {local} → {peer}", flow.flow_id),
            format!(
                "Correlation  {}    Namespace  {}",
                flow.correlation_confidence,
                flow.netns_inum
                    .map_or_else(|| "unknown".to_owned(), |id| id.to_string())
            ),
        ];
        if let Some(association) = &explanation.nat_association {
            lines.push(format!(
                "NAT {} side  {} association · {} translation · {}",
                association.side,
                association.confidence,
                association.translation_confidence,
                association.evidence.evidence_id
            ));
        }
        if let Some(note) = explanation.nat_association_note {
            lines.push(note.to_owned());
        }
        for diagnosis in &explanation.diagnoses {
            lines.push(String::new());
            lines.push(format!(
                "[{}] {}",
                diagnosis.confidence,
                diagnosis.code.replace('_', " ")
            ));
            lines.push(diagnosis.observation.to_owned());
            let ids = diagnosis
                .evidence_ids
                .iter()
                .take(8)
                .map(String::as_str)
                .collect::<Vec<_>>();
            let extra = diagnosis.evidence_ids.len().saturating_sub(ids.len());
            lines.push(format!(
                "Evidence  {}{}",
                ids.join(", "),
                if extra > 0 {
                    format!(" (+{extra} more)")
                } else {
                    String::new()
                }
            ));
            lines.extend(
                diagnosis
                    .alternatives
                    .iter()
                    .map(|line| format!("  {line}")),
            );
        }
        lines
    }

    fn coverage_lines(&self) -> Vec<String> {
        let mut lines = vec!["Capture gaps".to_owned()];
        if self.review.capture_gaps().is_empty() {
            lines.push("No gaps reported in capture metadata.".to_owned());
        } else {
            lines.extend(
                self.review
                    .capture_gaps()
                    .iter()
                    .map(|item| format!("  {}", clean(item))),
            );
        }
        lines.extend([String::new(), "Active probes".to_owned()]);
        if self.review.active_probes().is_empty() {
            lines.push("No active probe data reported.".to_owned());
        } else {
            lines.extend(
                self.review
                    .active_probes()
                    .iter()
                    .map(|item| format!("  {}", clean(item))),
            );
        }
        lines.extend([String::new(), "Blind spots".to_owned()]);
        lines.extend(
            self.review
                .blind_spots()
                .iter()
                .map(|item| format!("  {}", clean(item))),
        );
        lines
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return true;
        }
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return false;
        }
        if self.is_live && key.code == KeyCode::Char('f') {
            self.follow = true;
            self.focus = Focus::Flows;
            self.flow = Cursor::default();
            self.details = Details::Event;
            self.load_flow();
            return true;
        }
        if self.is_live
            && matches!(
                key.code,
                KeyCode::Tab
                    | KeyCode::BackTab
                    | KeyCode::Enter
                    | KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::PageUp
                    | KeyCode::PageDown
                    | KeyCode::Home
                    | KeyCode::End
                    | KeyCode::Char('e' | 'd' | 'c' | 'j' | 'k')
            )
        {
            self.follow = false;
        }
        match key.code {
            KeyCode::Tab => self.advance_focus(false),
            KeyCode::BackTab => self.advance_focus(true),
            KeyCode::Enter => match self.focus {
                Focus::Flows => self.focus = Focus::Timeline,
                Focus::Timeline => self.show_details(Details::Event),
                Focus::Details => {}
            },
            KeyCode::Char('e') => self.show_details(Details::Event),
            KeyCode::Char('d') => self.show_details(Details::Diagnoses),
            KeyCode::Char('c') => self.show_details(Details::Coverage),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::PageUp => self.move_by(-8),
            KeyCode::PageDown => self.move_by(8),
            KeyCode::Home => self.move_by(isize::MIN),
            KeyCode::End => self.move_by(isize::MAX),
            KeyCode::Left if self.focus == Focus::Details => {
                self.detail_scroll.1 = self.detail_scroll.1.saturating_sub(4);
            }
            KeyCode::Right if self.focus == Focus::Details => {
                self.detail_scroll.1 = self.detail_scroll.1.saturating_add(4);
            }
            _ => {}
        }
        true
    }

    fn advance_focus(&mut self, backwards: bool) {
        self.focus = match (self.focus, backwards) {
            (Focus::Flows, false) | (Focus::Details, true) => Focus::Timeline,
            (Focus::Timeline, false) | (Focus::Flows, true) => Focus::Details,
            (Focus::Details, false) | (Focus::Timeline, true) => Focus::Flows,
        };
    }

    fn show_details(&mut self, details: Details) {
        self.focus = Focus::Details;
        if self.details != details {
            self.details = details;
            self.refresh_details();
        }
    }

    fn move_by(&mut self, delta: isize) {
        match self.focus {
            Focus::Flows => {
                let before = self.flow.selected;
                self.flow.move_by(delta, self.flows.len());
                if before != self.flow.selected {
                    self.load_flow();
                }
            }
            Focus::Timeline => {
                let before = self.evidence.selected;
                self.evidence.move_by(delta, self.timeline.len());
                if before != self.evidence.selected && self.details == Details::Event {
                    self.refresh_details();
                }
            }
            Focus::Details => {
                self.detail_scroll.0 = self
                    .detail_scroll
                    .0
                    .saturating_add_signed(delta)
                    .min(self.detail_lines.len().saturating_sub(self.detail_height));
            }
        }
    }

    fn render(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        frame.render_widget(Clear, area);
        frame.render_widget(Block::default().style(Style::new().bg(BACKGROUND)), area);
        if area.width < 44 || area.height < 14 {
            frame.render_widget(
                Paragraph::new("Resize the terminal · q quits").style(Style::new().fg(TEXT)),
                area,
            );
            return;
        }
        let [head, body, foot] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let gaps = self.review.capture_gaps().len();
        let status = if gaps == 0 {
            "no reported gaps".to_owned()
        } else {
            format!("{gaps} capture gaps")
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        " lnfr  ",
                        Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(self.filename.as_str(), Style::new().fg(TEXT)),
                ]),
                Line::from(vec![
                    Span::styled(
                        if self.is_live {
                            format!(
                                " {} flows  ·  {}  ·  ",
                                self.flows.len(),
                                if self.follow {
                                    "Following"
                                } else {
                                    "Reviewing"
                                }
                            )
                        } else {
                            format!(" {} flows  ·  ", self.flows.len())
                        },
                        Style::new().fg(DIM),
                    ),
                    Span::styled(
                        status,
                        Style::new().fg(if gaps == 0 { DIM } else { WARNING }),
                    ),
                ]),
            ]),
            head,
        );
        let (flows, timeline, details) = if body.width >= 120 {
            let [flows, right] =
                Layout::horizontal([Constraint::Percentage(52), Constraint::Fill(1)]).areas(body);
            let [timeline, details] =
                Layout::vertical([Constraint::Percentage(52), Constraint::Fill(1)]).areas(right);
            (flows, timeline, details)
        } else {
            let [flows, timeline, details] = Layout::vertical([
                Constraint::Percentage(34),
                Constraint::Percentage(32),
                Constraint::Fill(1),
            ])
            .areas(body);
            (flows, timeline, details)
        };
        self.render_flows(frame, flows);
        self.render_timeline(frame, timeline);
        self.render_details(frame, details);
        let shortcuts = if self.is_live {
            if area.width < 79 {
                " ↑↓ Move  Tab  e/d/c Views  f Follow  q Quit"
            } else {
                " ↑↓ Move  Tab Focus  e Event  d Diagnosis  c Coverage  f Follow  q Quit"
            }
        } else if area.width < 64 {
            " ↑↓ Move  Tab Focus  e/d/c Views  q Quit"
        } else {
            " ↑↓ Move  Tab Focus  e Event  d Diagnosis  c Coverage  q Quit"
        };
        frame.render_widget(Paragraph::new(shortcuts).style(Style::new().fg(DIM)), foot);
    }

    fn render_flows(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let block = panel(" Flows ", self.focus == Focus::Flows);
        if self.flows.is_empty() {
            frame.render_widget(
                Paragraph::new(if self.is_live {
                    "Waiting for TCP activity…"
                } else {
                    "No socket flows in this capture."
                })
                .style(Style::new().fg(DIM))
                .block(block),
                area,
            );
            return;
        }
        let window = self
            .flow
            .visible(self.flows.len(), usize::from(area.height.saturating_sub(3)));
        let rows = self.flows[window.clone()].iter().map(|(index, flow)| {
            let (local, peer) = endpoints(flow);
            let flow_id = flow.flow_id.as_str();
            Row::new([
                Cell::from(flow_id.strip_prefix("flow-").unwrap_or(flow_id)),
                Cell::from(
                    self.review
                        .first_estimated_wall_ns(*index)
                        .map_or_else(String::new, estimated_utc_time),
                ),
                Cell::from(local),
                Cell::from(peer),
                Cell::from(flow.event_count.to_string()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Fill(1),
                Constraint::Fill(1),
                Constraint::Length(4),
            ],
        )
        .header(table_header(["Flow", "First UTC", "Local", "Peer", "TCP"]))
        .block(block)
        .style(Style::new().fg(TEXT))
        .highlight_symbol("▸ ")
        .highlight_spacing(HighlightSpacing::Always)
        .row_highlight_style(
            Style::new()
                .bg(SELECTED)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD),
        );
        let mut state = TableState::default().with_selected(self.flow.selected - window.start);
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn render_timeline(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let title = self.flows.get(self.flow.selected).map_or_else(
            || " Evidence timeline ".to_owned(),
            |(_, flow)| format!(" Evidence timeline · {} ", flow.flow_id),
        );
        let block = panel(title, self.focus == Focus::Timeline);
        if self.timeline.is_empty() {
            frame.render_widget(
                Paragraph::new("No evidence for this view.")
                    .style(Style::new().fg(DIM))
                    .block(block),
                area,
            );
            return;
        }
        let window = self.evidence.visible(
            self.timeline.len(),
            usize::from(area.height.saturating_sub(3)),
        );
        let start = self.timeline[0].stamp;
        let rows = self.timeline[window.clone()].iter().map(|event| {
            Row::new([
                relative_time(event.stamp - start),
                event.id.clone(),
                event.label.clone(),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(11),
                Constraint::Length(10),
                Constraint::Fill(1),
            ],
        )
        .header(table_header(["Elapsed", "Evidence", "Observation"]))
        .block(block)
        .style(Style::new().fg(TEXT))
        .highlight_symbol("▸ ")
        .highlight_spacing(HighlightSpacing::Always)
        .row_highlight_style(
            Style::new()
                .bg(SELECTED)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD),
        );
        let mut state = TableState::default().with_selected(self.evidence.selected - window.start);
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn render_details(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let title = match self.details {
            Details::Event => self.timeline.get(self.evidence.selected).map_or_else(
                || " Event ".to_owned(),
                |row| format!(" Event · {} ", row.id),
            ),
            Details::Diagnoses => " Diagnoses ".to_owned(),
            Details::Coverage => " Capture coverage ".to_owned(),
        };
        let rows = usize::from(area.height.saturating_sub(2)).max(1);
        let cols = usize::from(area.width.saturating_sub(2)).max(1);
        self.detail_height = rows;
        self.detail_scroll.0 = self
            .detail_scroll
            .0
            .min(self.detail_lines.len().saturating_sub(rows));
        let lines: Vec<_> = self
            .detail_lines
            .iter()
            .skip(self.detail_scroll.0)
            .take(rows)
            .map(|line| Line::from(line.as_str()))
            .collect();
        let widest = lines.iter().map(Line::width).max().unwrap_or(0);
        self.detail_scroll.1 = self.detail_scroll.1.min(widest.saturating_sub(cols));
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel(title, self.focus == Focus::Details))
                .scroll((0, self.detail_scroll.1.min(usize::from(u16::MAX)) as u16))
                .style(Style::new().fg(TEXT)),
            area,
        );
    }
}

fn panel<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::bordered()
        .title(title)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { ACCENT } else { BORDER }))
        .title_style(Style::new().fg(if focused { ACCENT } else { TEXT }))
}

fn table_header<const N: usize>(columns: [&'static str; N]) -> Row<'static> {
    Row::new(columns.map(Cell::from)).style(Style::new().fg(DIM).add_modifier(Modifier::BOLD))
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '�' } else { ch })
        .collect()
}

fn format_endpoint(endpoint: Endpoint) -> String {
    match (endpoint.address, endpoint.port) {
        (std::net::IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        (ip, Some(port)) => format!("{ip}:{port}"),
        (ip, None) => ip.to_string(),
    }
}

fn endpoints(flow: &FlowSummary) -> (String, String) {
    if let Some(tuple) = flow.tuple {
        (format_endpoint(tuple.local), format_endpoint(tuple.remote))
    } else {
        (
            "—".to_owned(),
            flow.requested_peer.map_or_else(
                || "—".to_owned(),
                |peer| format!("{} (req.)", format_endpoint(peer)),
            ),
        )
    }
}

fn estimated_utc_time(ns: u64) -> String {
    let seconds = (ns / 1_000_000_000) % 86_400;
    let hours = seconds / 3_600;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    format!("~{hours:02}:{minutes:02}:{seconds:02}")
}

fn relative_time(ns: u64) -> String {
    format!("+{}.{:03}s", ns / 1_000_000_000, (ns / 1_000_000) % 1000)
}

fn event_label(event: &Value) -> String {
    match event["record"].as_str() {
        Some("socket_state") => format!(
            "{} → {}",
            tcp_state(event["oldstate"].as_i64()),
            tcp_state(event["newstate"].as_i64())
        ),
        Some("tcp_connect") => match event["result"].as_i64() {
            Some(0) => "TCP connect succeeded".to_owned(),
            Some(result) if result == -i64::from(libc::ECONNREFUSED) => {
                "TCP connect refused".to_owned()
            }
            Some(result) if result == -i64::from(libc::ETIMEDOUT) => {
                "TCP connect timed out".to_owned()
            }
            Some(result) if result == -i64::from(libc::EINPROGRESS) => {
                "TCP connect in progress".to_owned()
            }
            Some(result) => format!("TCP connect returned {result}"),
            None => "TCP connect".to_owned(),
        },
        Some("tcp_accept") => "TCP accept".to_owned(),
        Some("tcp_retransmit") => "TCP retransmit".to_owned(),
        Some("tc_packet") => format!(
            "TC {}",
            event["direction"].as_str().map(clean).unwrap_or_default()
        ),
        Some("conntrack_nat") => "Conntrack NAT (receipt)".to_owned(),
        _ => "Observation".to_owned(),
    }
}

fn tcp_state(state: Option<i64>) -> String {
    match state {
        Some(1) => "ESTABLISHED",
        Some(2) => "SYN_SENT",
        Some(3) => "SYN_RECV",
        Some(4) => "FIN_WAIT1",
        Some(5) => "FIN_WAIT2",
        Some(6) => "TIME_WAIT",
        Some(7) => "CLOSE",
        Some(8) => "CLOSE_WAIT",
        Some(9) => "LAST_ACK",
        Some(10) => "LISTEN",
        Some(11) => "CLOSING",
        Some(12) => "NEW_SYN_RECV",
        Some(value) => return format!("STATE_{value}"),
        None => "—",
    }
    .to_owned()
}

pub fn run(path: &Path) -> Result<()> {
    let review = Review::load(path)?;
    terminal_session(|terminal, stop| {
        let mut app = App::new(&review, path);
        terminal.draw(|frame| app.render(frame))?;
        while !stop.load(Ordering::Relaxed) {
            if !handle_input(terminal, &mut app)? {
                break;
            }
        }
        Ok(())
    })
}

pub fn run_live(netns_inum: Option<u32>, summary: bool) -> Result<()> {
    check_terminal()?;
    let mut capture = live::Capture::start(netns_inum)?;
    let result = terminal_session(|terminal, stop| {
        let mut review = capture.review()?;
        let mut app = App::for_source(&review, capture.label().to_owned(), true, None);
        let mut next_refresh = Instant::now();
        let mut changed = false;
        terminal.draw(|frame| app.render(frame))?;
        while !stop.load(Ordering::Relaxed) {
            changed |= capture.update()?;
            if changed && Instant::now() >= next_refresh {
                let view = app.live_view();
                drop(app);
                review = capture.review()?;
                app = App::for_source(&review, capture.label().to_owned(), true, Some(view));
                terminal.draw(|frame| app.render(frame))?;
                next_refresh = Instant::now() + Duration::from_millis(200);
                changed = false;
            }
            if !handle_input(terminal, &mut app)? {
                break;
            }
        }
        Ok(())
    });
    let stopped = capture.stop();
    result.and(stopped)?;
    if summary {
        let report = capture
            .summary()
            .context("live collector did not emit a summary")?;
        print!("{report}");
    }
    Ok(())
}

fn check_terminal() -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "lnfr tui requires an interactive terminal"
    );
    Ok(())
}

fn terminal_session(
    run: impl FnOnce(&mut DefaultTerminal, &AtomicBool) -> Result<()>,
) -> Result<()> {
    check_terminal()?;
    let stop = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stop)).context("register interrupt handler")?;
    flag::register(SIGTERM, Arc::clone(&stop)).context("register termination handler")?;
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = ratatui::try_restore();
            return Err(error).context("initialize terminal");
        }
    };
    let result = run(&mut terminal, &stop);
    let restored = ratatui::try_restore().context("restore terminal");
    result.and(restored)
}

fn handle_input(terminal: &mut DefaultTerminal, app: &mut App<'_>) -> Result<bool> {
    match event::poll(Duration::from_millis(60)) {
        Ok(false) => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(true),
        other => other?,
    };
    match event::read()? {
        Event::Key(key) if !app.handle_key(key) => return Ok(false),
        Event::Key(_) | Event::Resize(_, _) => {
            terminal.draw(|frame| app.render(frame))?;
        }
        _ => {}
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    const CAPTURE: &[u8] = br#"{"record":"capture_start","schema_version":2,"active_probes":["sock:inet_sock_set_state"],"disabled_probes":{"tcp:tcp_retransmit_skb":"fixture unavailable"}}
{"record":"socket_state","schema_version":2,"hook":"sock:inet_sock_set_state","monotonic_ns":10,"estimated_wall_ns":97445000000000,"netns_inum":11,"oldstate":7,"newstate":2,"local":{"address":"192.0.2.1","port":40000},"remote":{"address":"192.0.2.2","port":8080}}
{"record":"tcp_connect","schema_version":2,"hook":"fexit/inet_stream_connect","monotonic_ns":20,"estimated_wall_ns":97446000000000,"netns_inum":11,"result":0,"local":{"address":"192.0.2.1","port":40000},"remote":{"address":"192.0.2.2","port":8080}}
{"record":"tcp_connect","schema_version":2,"hook":"fexit/inet_stream_connect","monotonic_ns":30,"netns_inum":11,"result":-111,"requested_peer":{"address":"192.0.2.2","port":9000}}
{"record":"capture_end","schema_version":2,"received":3,"stats":{"submitted":3,"ring_lost":2,"rate_limited":0}}"#;

    fn screen(app: &mut App<'_>, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut output = String::new();
        for y in 0..height {
            for x in 0..width {
                output.push_str(buffer[(x, y)].symbol());
            }
            output.push('\n');
        }
        output
    }

    fn press(app: &mut App<'_>, code: KeyCode) {
        assert!(app.handle_key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    #[test]
    fn renders_flows_and_switches_evidence_diagnosis_and_coverage() {
        let capture = Review::from_jsonl(CAPTURE).unwrap();
        let mut app = App::new(&capture, Path::new("example.jsonl"));
        let first = screen(&mut app, 124, 36);
        for label in [
            "example.jsonl",
            "Evidence timeline · flow-2",
            "line-2",
            "CLOSE → SYN_SENT",
            "2 capture gaps",
        ] {
            assert!(first.contains(label), "{label} missing from {first}");
        }

        for width in [78, 124] {
            let view = screen(&mut app, width, 36);
            let mut lines = view.lines();
            let header = lines.find(|line| line.contains("First UTC")).unwrap();
            let time_start = header.find("First UTC").unwrap();
            // The border and selection marker occupy more bytes than terminal cells.
            let time_column = header[..time_start].chars().count();
            let first_flow = lines.next().unwrap();
            let second_flow = lines.next().unwrap();
            assert_eq!(first_flow.split_whitespace().nth(1), Some("2"));
            assert!(first_flow.contains("~03:04:05"));
            assert!(first_flow.contains("192.0.2.1:40000"));
            assert_eq!(second_flow.split_whitespace().nth(1), Some("4"));
            assert_eq!(
                second_flow
                    .chars()
                    .skip(time_column)
                    .take(9)
                    .collect::<String>(),
                "         "
            );
        }

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Down);
        assert!(screen(&mut app, 124, 36).contains("Event · line-3"));
        press(&mut app, KeyCode::BackTab);
        press(&mut app, KeyCode::Down);
        assert!(screen(&mut app, 124, 36).contains("TCP connect refused"));
        press(&mut app, KeyCode::Char('d'));
        let diagnosis = screen(&mut app, 124, 36);
        assert!(diagnosis.contains("[confirmed] connection refused"));
        assert!(diagnosis.contains("Evidence  line-4"));
        press(&mut app, KeyCode::Char('c'));
        let coverage = screen(&mut app, 80, 36);
        for label in [
            "Capture coverage",
            "2 ring-buffer loss",
            "Active probes",
            "Blind spots",
        ] {
            assert!(coverage.contains(label), "{label} missing from {coverage}");
        }
    }

    #[test]
    fn handles_empty_small_capture_and_escapes_terminal_control_characters() {
        let events = br#"{"record":"capture_start","schema_version":2,"active_probes":[]}
{"record":"capture_end","schema_version":2,"received":0,"stats":{"submitted":0,"ring_lost":0,"rate_limited":0}}"#;
        let capture = Review::from_jsonl(events).unwrap();
        let mut app = App::new(&capture, Path::new("unsafe\x1bname.jsonl"));
        assert!(screen(&mut app, 72, 23).contains("No socket flows"));
        assert!(!screen(&mut app, 72, 23).contains('\x1b'));
        assert!(screen(&mut app, 40, 12).contains("Resize the terminal"));
        assert!(!app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    }

    #[test]
    fn live_refresh_keeps_review_selection_until_follow_resumes() {
        let initial = CAPTURE
            .split(|&byte| byte == b'\n')
            .take(3)
            .collect::<Vec<_>>()
            .join(&b'\n');
        let before = Review::from_live_window(&initial, 0).unwrap();
        let mut app = App::for_source(&before, "Live TCP".to_owned(), true, None);
        assert_eq!(app.timeline[app.evidence.selected].id, "line-3");
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.timeline[app.evidence.selected].id, "line-2");
        let view = app.live_view();

        let after = Review::from_live_window(CAPTURE, 0).unwrap();
        let mut app = App::for_source(&after, "Live TCP".to_owned(), true, Some(view));
        let view = screen(&mut app, 124, 36);
        assert!(view.contains("Reviewing"));
        assert!(
            view.lines()
                .any(|line| line.split_whitespace().nth(1) == Some("2")
                    && line.contains("~03:04:05"))
        );
        assert_eq!(app.timeline[app.evidence.selected].id, "line-2");
        press(&mut app, KeyCode::Char('f'));
        assert!(screen(&mut app, 124, 36).contains("Following"));
        assert_eq!(
            app.timeline[app.evidence.selected].label,
            "TCP connect refused"
        );
    }
}
