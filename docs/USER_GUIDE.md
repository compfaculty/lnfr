# NFR user guide

## Build and check your host

Build on x86-64 Linux. NFR is tested on Kali Linux. The build needs a Rust
toolchain with Cargo and edition 2024 support, Clang with the BPF backend,
a C toolchain, Linux and libbpf headers, libelf and zlib development
libraries, and pkg-config. Cargo compiles the BPF object and generates its
Rust bindings during the build.

```bash
cargo build --locked
target/debug/nfr doctor
```

Capture needs readable kernel BTF at `/sys/kernel/btf/vmlinux`, access to the
`sock:inet_sock_set_state` tracepoint, and permission to load and attach BPF
tracing programs. `doctor` checks whether candidate hooks are visible.
The `capture_start` record shows the probes that actually attached and why
any were disabled. Optional hooks and their requirements are listed in the
[architecture guide](ARCHITECTURE.md#tcp-lifecycle).

## Watch TCP activity live

```bash
sudo -v
target/debug/nfr tui --live
```

Run both commands in the same terminal. The viewer launches a privileged TCP
collector and follows the most recently active flow. Moving through the flows
or events keeps your selection while capture continues. Press **f** to resume
following and **q** to stop the collector and exit. The live window retains up
to 4,096 events or 2 MiB of event data and evicts older events as needed. Use a
saved capture when you need to keep the evidence after exiting.

## Capture and inspect a session

```bash
sudo target/debug/nfr capture --duration 10s > session.jsonl
target/debug/nfr tui --input session.jsonl
```

Reproduce the issue from another terminal during the capture. The duration
can be 1–300 seconds. Ctrl+C or SIGTERM ends the capture early and lets the
collector detach, drain the ring, and write its summary.

In the viewer, use **↑/↓** to select a flow or evidence row and **Tab** or
**Enter** to move between panes. **e** shows the original event, **d** shows
diagnoses and their evidence IDs, and **c** shows coverage, gaps, and blind
spots. Use the arrow keys to scroll the detail pane.

For command-line analysis, list the flows, then enter one of the reported IDs
from the same file.

```bash
target/debug/nfr flows --input session.jsonl
read -r -p 'Flow ID: ' flow_id
target/debug/nfr explain --input session.jsonl --flow "$flow_id"
```

The explanation includes the original event for each evidence ID, in monotonic
time order. An ID such as `line-2` points to line 2 of the capture. Confirmed
diagnosis confidence describes what the cited event directly reports.
Correlation confidence describes how confidently NFR assigned the events to the
same flow. Both flow and evidence IDs are local to the capture.

### Focus a capture

- Use `--netns-inum "$(stat -Lc %i /proc/PID/ns/net)"` on `capture` to
  filter TCP events by the socket's network namespace. Replace `PID` with a
  process in that namespace.
- Use `--tgid PID` to filter by the task executing the hook. Retransmits can
  run in timer or interrupt context, so prefer the namespace filter when
  investigating retries.
- Keep captures short on busy hosts. Saved-capture analysis accepts up to
  100,000 events and 64 MiB of input, with a 16 KiB limit per line.

Capture files may contain addresses, ports, MAC addresses, timestamps, and
process or namespace identifiers. Review them before sharing.

## Add network context

Enable the relevant observer when capturing. Run in the namespace that owns
the interface, bridge, forwarding path, or NAT state. To enter a named network
namespace while keeping the host's tracefs visible, use
`sudo nsenter --net=/run/netns/NAME -- "$PWD/target/debug/nfr" capture ...`.

| Capture option | Report subcommand | What the observation tells you |
| --- | --- | --- |
| `--conntrack` | `nat` | Original and translated TCP endpoints reported by conntrack. It listens for events during capture. |
| `--tc-interface eth0` | `tc` | TCP header metadata seen at TCX ingress and egress on the selected interface. |
| `--bridge-interface br0` | `bridge` | Ingress and selected output ports at Linux software bridge forwarding, with MAC addresses and EtherType. |
| `--routing` | `routes` | The attached route's selected output interface at IPv4 or IPv6 forwarding entry, with ingress interface, addresses, and TTL or hop limit. |

For example, on the host or in the namespace performing NAT:

```bash
sudo target/debug/nfr capture --conntrack --duration 10s > nat-session.jsonl
target/debug/nfr nat --input nat-session.jsonl
```

Each report reads the saved file with `--input`. `explain` includes TC and
NAT observations when the correlation rules can associate them with a flow.
Bridge and route reports describe what the corresponding kernel hooks
observed. A selected egress interface describes a forwarding decision at that
point. Actual transmission and delivery are outside that observation.

Conntrack and TCX require `CAP_NET_ADMIN` in the selected namespace in addition
to the tracing permissions. Bridge capture requires BTF for the loaded bridge
module. `--netns-inum` filters the TCP socket probes only. The optional
observers are scoped to the capture process's namespace and cannot be combined
with `--tgid`.

## Troubleshoot capture and coverage

| Symptom | What to check |
| --- | --- |
| Live mode asks for sudo authorization | Run `sudo -v` in the same terminal, then rerun the viewer as your normal user. |
| The collector cannot load or attach | Run `doctor`, check the required state tracepoint and BTF, and verify capture privileges. Try `capture --state-only` to isolate the state probe from optional TCP hooks. |
| An optional network observer fails | Check the capture namespace, interface name, and feature support. Retry without that option to capture TCP lifecycle events. |
| The capture is missing expected evidence | Check **c** in the viewer, `capture_start` for attached and disabled probes, and `capture_end` for loss counters. Check the capture window and filter scope. |

The capture summary counts ring buffer reservation failures, deliberate rate
limiting, and failed connect timing tracking separately. A missing end record
also limits what you can conclude about the capture. When completion evidence
is missing, a connection attempt may remain unknown. A recorded retransmit
shows that TCP retried. Locating a loss requires evidence beyond that event.
