# Linux Network Flight Recorder (NFR)

**Codex-ready development plan for RustRover on macOS and Linux target `kali-z570`.**

## Objective

Build a low-overhead, read-only Linux networking observability tool that reconstructs the *observable* path of a flow through socket/TCP, routing-related events, skb drops, netfilter/conntrack, bridge, and TC stages. Report facts separately from hypotheses, with explicit confidence and blind spots. This is **not** a Wireshark replacement in packet-byte capture, nor a guarantee of perfect per-packet tracing.

![NFR live TCP view showing active flows, an evidence timeline, and event details](docs/images/project-image.png)

## Documents

- [`AGENTS.md`](AGENTS.md): instructions Codex should always read.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): architecture, event model, correlation constraints, hook strategy.
- [`docs/ROADMAP.md`](docs/ROADMAP.md): development phases, deliverables, acceptance criteria.
- [`docs/REMOTE_DEV.md`](docs/REMOTE_DEV.md): macOS/RustRover ↔ Kali workflow, preflight and troubleshooting.
- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md): repeatable network namespace and fault-injection tests.
- [`prompts/CODEX_TASKS.md`](prompts/CODEX_TASKS.md): scoped prompts for incremental Codex implementation.
- [`scripts/preflight.sh`](scripts/preflight.sh): read-only probe to run on `kali-z570`.

## Decision record

- **Kernel probes:** C, libbpf, CO-RE/BTF; **userspace:** Rust, libbpf-rs, Tokio, Ratatui (later).
- **Initial environment:** x86_64 Kali Linux (`kali-z570`), accessed from macOS using RustRover.
- **No production policies, packet modification, or automatic enforcement in MVP.**
- **No root IDE:** development with unprivileged user, least-privilege dedicated test runner for BPF load/attach. Avoid broad setcap on RustRover or on arbitrary binaries.
- **Must verify runtime capabilities before choosing tracepoints/attachments.**

## Start here

1. On macOS verify `ssh kali-z570` works (your SSH config should resolve the host and key).
2. Copy `scripts/preflight.sh` to the Kali host and run `bash preflight.sh`. Review results (kernel/BTF/toolchain/capabilities).
3. Open the repo in **RustRover Remote Development over SSH** if supported by your installed IDE/version, or use locally with SSH-based build/run commands. The repository and toolchain should live on Kali.
4. In Codex, provide `AGENTS.md` and `prompts/CODEX_TASKS.md`; begin only with **Task 0**.

See the other documents before writing implementation code.

## TCP capture

Build on x86_64 Kali as your normal user. The build needs Rust with rustfmt, Clang
with the BPF backend, Linux and libbpf headers, libelf and zlib development
libraries, a C toolchain, and pkg-config. Cargo uses `libbpf-cargo` to compile the
BPF object and generate the Rust skeleton.

```bash
cargo build --locked
target/debug/nfr doctor
sudo target/debug/nfr capture --duration 10s >session.jsonl
```

The capture emits V2 JSONL with start and end records and TCP connect results,
successful kernel accepts, socket state changes, and retransmit observations.
The end record includes submitted, received, ring-buffer loss, rate-limit, and
connect-timing tracking counters. Ctrl+C and SIGTERM stop capture cleanly.

Use `--netns-inum "$(stat -Lc %i /proc/PID/ns/net)"` to filter by the socket's
network namespace. Use `--tgid PID` for an execution-context filter. Timer and
interrupt events can run outside the original process context, so the namespace
filter is more suitable when you need retransmit coverage. Captures contain
local and remote addresses and ports. Keep them local and remove them when no
longer needed.

The probes need readable kernel BTF and permission to load and attach tracing
programs. `doctor` lists candidate hooks, and the capture header lists the hooks
that actually attached and any disabled hooks. Use `--state-only` to isolate
the socket-state tracepoint if an optional program fails to load.
See [Phase 2 verification](docs/TEST_PLAN.md#phase-2-tcp-veth-fixtures) for the
Kali integration fixture.

## Analyze a saved capture

Run both commands as your normal user. `flows` prints one JSONL summary per
flow. Use a displayed flow ID with the same capture file:

```bash
target/debug/nfr flows --input session.jsonl
target/debug/nfr explain --input session.jsonl --flow flow-2
```

`explain` prints the timeline in monotonic order and retains each original JSON
event under a line-based evidence ID. A confirmed diagnosis means its cited
events directly report the observation. Correlation confidence describes how
events were assigned to the flow. Capture gaps and blind spots are included in
the report.

## Inspect NAT translations

Use `--conntrack` in the network namespace that performs NAT. The subscriber needs
`CAP_NET_ADMIN` there, in addition to the privileges required by the TCP probes.
When present, `--netns-inum` filters the TCP socket events only.

```bash
sudo target/debug/nfr capture --conntrack --duration 10s >nat-session.jsonl
target/debug/nfr nat --input nat-session.jsonl
```

`nat` lists conntrack observations with their evidence IDs. `explain` can also
show a possible association between a socket flow and a conntrack translation.
The association preserves the separate socket perspectives and leaves ambiguous
matches unresolved.

## Observe TC ingress and egress

Run capture in the network namespace that owns the interface. TCX needs
`CAP_NET_ADMIN` in that namespace and the privileges required by the BPF
loader. For a named namespace, use `nsenter --net` so tracefs stays visible.

```bash
sudo target/debug/nfr capture --tc-interface eth0 --duration 10s >tc-session.jsonl
target/debug/nfr tc --input tc-session.jsonl
```

`tc` lists timestamped ingress and egress observations with evidence IDs.
The optional probes record TCP header metadata and let packet processing
continue. `explain` shows matching observations when the tuple, direction,
namespace, and time window identify a single socket flow.

## Observe bridge forwarding

Run capture in the namespace that owns the Linux bridge. This optional probe
requires the loaded bridge module's BTF and tracing privileges. Use
`nsenter --net` for a named namespace when the capture needs the host's tracefs.

```bash
sudo target/debug/nfr capture --bridge-interface br0 --duration 10s >bridge-session.jsonl
target/debug/nfr bridge --input bridge-session.jsonl
```

The report lists the ingress and selected egress ports, MAC addresses, and
EtherType. It records software port selection at the bridge hook. Later
filtering, queuing, and delivery are outside this observation.

## Observe IP forwarding

Use `--routing` in the namespace that routes the traffic. For a named
namespace, enter it with `nsenter --net` and retain the host tracefs mount.

```bash
sudo target/debug/nfr capture --routing --duration 10s >routing-session.jsonl
target/debug/nfr routes --input routing-session.jsonl
```

The report shows IPv4 and IPv6 addresses, ingress and selected egress
ifindices, and TTL or hop limit at forwarding entry. The selected egress is
the one on the skb's attached route at that hook. Later policy and actual
output are outside the observation.

## Watch TCP activity live

```bash
cargo build --locked
sudo -v
target/debug/nfr tui --live
```

Run these commands in the same terminal on Kali. The viewer runs as your
normal user and starts the BPF collector with sudo. The table updates as new
TCP events arrive and follows the most recently active flow. Navigating to a
flow or evidence row keeps that selection while capture continues. Press
**f** to resume following and **q** to stop capture and return to the shell.
The live view keeps up to 4,096 recent events or 2 MiB of event data.

To generate an observable connection attempt from another terminal, run
`curl --max-time 2 http://127.0.0.1:1`.

## Browse a saved capture in the terminal

```bash
target/debug/nfr tui --input session.jsonl
```

Use **Up/Down** to select a flow or evidence row, **Tab** to move between
panes, and **Enter** to open the next pane. **e** shows the original event,
**d** shows diagnoses and their evidence IDs, and **c** shows active probes,
capture gaps, and blind spots. The detail pane supports arrow keys for
scrolling. **q** exits the TUI.
