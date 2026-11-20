use std::{
    collections::VecDeque,
    io::{self, BufRead, BufReader, Read},
    process::{ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::{self, JoinHandle},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::flows::Review;

const MAX_LINE: u64 = 16 * 1024;
const MAX_EVENTS: usize = 4_096;
const MAX_BYTES: usize = 2 * 1024 * 1024;

enum Update {
    Line(String),
    Finished(Result<()>),
}

pub(super) struct Capture {
    window: Window,
    input: Option<ChildStdin>,
    updates: Receiver<Update>,
    worker: Option<JoinHandle<()>>,
    finished: bool,
}

#[derive(Default)]
struct Window {
    start: Option<String>,
    end: Option<String>,
    events: VecDeque<String>,
    bytes: usize,
    evicted: usize,
}

impl Window {
    fn push(&mut self, line: String) -> Result<()> {
        #[derive(Deserialize)]
        struct Record<'a> {
            record: &'a str,
        }
        let tag =
            serde_json::from_str::<Record<'_>>(&line).context("read live capture record type")?;
        match tag.record {
            "capture_start" => {
                ensure!(self.start.is_none(), "duplicate live capture header");
                self.start = Some(line);
            }
            "capture_end" => {
                ensure!(
                    self.start.is_some() && self.end.is_none(),
                    "unexpected live capture summary"
                );
                self.end = Some(line);
            }
            "socket_state" | "tcp_connect" | "tcp_accept" | "tcp_retransmit" => {
                ensure!(
                    self.start.is_some() && self.end.is_none(),
                    "live event outside capture"
                );
                self.bytes += line.len();
                self.events.push_back(line);
                while self.events.len() > MAX_EVENTS || self.bytes > MAX_BYTES {
                    self.bytes -= self.events.pop_front().expect("over capacity").len();
                    self.evicted += 1;
                }
            }
            other => bail!("unexpected live capture record {other}"),
        }
        Ok(())
    }

    fn review(&self) -> Result<Review> {
        let mut jsonl = Vec::with_capacity(self.bytes);
        for line in self.start.iter().chain(&self.events).chain(&self.end) {
            jsonl.extend_from_slice(line.as_bytes());
        }
        Review::from_live_window(&jsonl, self.evicted)
    }
}

impl Capture {
    pub(super) fn start(netns_inum: Option<u32>) -> Result<Self> {
        let executable = std::env::current_exe().context("locate lnfr capture executable")?;
        // geteuid has no pointer arguments and does not modify process state.
        let root = unsafe { libc::geteuid() } == 0;
        let mut command = if root {
            Command::new(executable)
        } else {
            let mut sudo = Command::new("sudo");
            sudo.arg("-n").arg("--").arg(executable);
            sudo
        };
        command.args(["capture", "--stop-on-stdin-eof"]);
        if let Some(inode) = netns_inum {
            command.arg("--netns-inum").arg(inode.to_string());
        }
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start live capture process")?;
        let input = child.stdin.take().expect("piped child stdin");
        let stdout = child.stdout.take().expect("piped child stdout");
        let stderr = child.stderr.take().expect("piped child stderr");
        let (send, updates) = mpsc::sync_channel(256);
        let worker = thread::spawn(move || {
            let errors = thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut bytes = Vec::new();
                let _ = reader.by_ref().take(8_192).read_to_end(&mut bytes);
                let _ = io::copy(&mut reader, &mut io::sink());
                String::from_utf8_lossy(&bytes).trim().to_owned()
            });
            let mut reader = BufReader::new(stdout);
            let streamed = (|| -> Result<()> {
                loop {
                    let mut line = String::new();
                    let size = reader
                        .by_ref()
                        .take(MAX_LINE + 1)
                        .read_line(&mut line)
                        .context("read live capture")?;
                    if size == 0 {
                        return Ok(());
                    }
                    ensure!(
                        size as u64 <= MAX_LINE && line.ends_with('\n'),
                        "live capture emitted an invalid JSONL line"
                    );
                    if send.send(Update::Line(line)).is_err() {
                        return Ok(());
                    }
                }
            })();
            drop(reader);
            let status = child.wait();
            let stderr = errors.join().unwrap_or_default();
            let result = streamed.and_then(|()| {
                let status = status.context("wait for live capture")?;
                if !status.success() {
                    if stderr.contains("a password is required") {
                        bail!("live capture needs sudo authorization. Run sudo -v in this terminal, then retry");
                    }
                    bail!("live capture {status}: {stderr}");
                }
                Ok(())
            });
            let _ = send.send(Update::Finished(result));
        });
        Ok(Self {
            window: Window::default(),
            input: Some(input),
            updates,
            worker: Some(worker),
            finished: false,
        })
    }

    pub(super) fn update(&mut self) -> Result<bool> {
        let mut changed = false;
        for _ in 0..512 {
            match self.updates.try_recv() {
                Ok(Update::Line(line)) => {
                    self.window.push(line)?;
                    changed = true;
                }
                Ok(Update::Finished(result)) => {
                    self.finished = true;
                    result?;
                    ensure!(
                        self.window.end.is_some(),
                        "live capture ended without a summary"
                    );
                    return Ok(true);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) if self.finished => break,
                Err(TryRecvError::Disconnected) => {
                    bail!("live capture reader stopped unexpectedly")
                }
            }
        }
        Ok(changed)
    }

    pub(super) fn review(&self) -> Result<Review> {
        self.window.review()
    }

    pub(super) fn label(&self) -> &'static str {
        if self.window.end.is_some() {
            "Capture stopped"
        } else if self.window.start.is_some() {
            "Live TCP"
        } else {
            "Starting capture"
        }
    }

    pub(super) fn summary(&self) -> Option<&str> {
        self.window.end.as_deref()
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        self.input.take();
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let mut result = Ok(());
        // Drain the pipe while the loader detaches and writes its final summary.
        while let Ok(update) = self.updates.recv() {
            match update {
                Update::Line(line) => {
                    if let Err(error) = self.window.push(line)
                        && result.is_ok()
                    {
                        result = Err(error);
                    }
                }
                Update::Finished(status) => {
                    if result.is_ok() {
                        result = status;
                    }
                }
            }
        }
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("live capture reader panicked"))?;
        result
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_stream_ids_stable_and_labels_rolling_history() {
        let mut window = Window::default();
        window
            .push(
                "{\"schema_version\":2,\"record\":\"capture_start\",\"active_probes\":[]}\n".into(),
            )
            .unwrap();
        for n in 0..=MAX_EVENTS {
            window.push(format!("{{\"schema_version\":2,\"record\":\"tcp_connect\",\"monotonic_ns\":{n},\"result\":0}}\n")).unwrap();
        }
        assert_eq!(window.evicted, 1);
        let review = window.review().unwrap();
        assert_eq!(review.summaries().next().unwrap().flow_id, "flow-3");
        assert_eq!(review.summaries().count(), MAX_EVENTS);
        assert!(
            review
                .capture_gaps()
                .iter()
                .any(|gap| gap.contains("rotated out 1"))
        );
    }

    #[test]
    fn drains_live_process_on_control_pipe_eof() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            r#"printf '%s\n' '{"schema_version":2,"record":"capture_start","active_probes":[]}'
cat >/dev/null
printf '%s\n' '{"schema_version":2,"record":"capture_end"}'"#,
        ]);
        let mut capture = Capture::spawn(command).unwrap();
        capture.stop().unwrap();
        assert!(capture.worker.is_none());
        assert!(capture.summary().unwrap().contains("capture_end"));
    }
}
