# Architecture

## Data flow

`lnfr` is a single Rust executable for x86-64 Linux. The build compiles the C
CO-RE probes in [bpf/lnfr.bpf.c](../bpf/lnfr.bpf.c) and generates a Rust
skeleton with `libbpf-cargo`.

```text
Kernel hooks → BPF ring buffer ───┐
                                 ├→ capture → JSONL → flow reports / saved TUI
Conntrack notifications (opt-in) ┘                  ↘ live TCP TUI
```

[The collector](../src/capture.rs) uses `libbpf-rs` to load and attach
the probes. [Event decoding](../src/event.rs) normalizes the fixed-size
binary records. [Flow analysis](../src/flows.rs) indexes the JSONL and
builds evidence-backed reports. [The Ratatui viewer](../src/tui.rs)
uses the same analysis for saved files and for the live collector's
rolling TCP window.

## Event format, clocks, and bounds

The collector emits versioned JSONL, starting with probe availability
and filter settings and ending with delivery and loss counters. The BPF
ring's V2 records are 128 bytes. Socket records can include IPv4 or IPv6
endpoints, socket namespace inode, socket cookie when present, and
execution-context task and cgroup IDs. Optional hooks carry their own
metadata in the same binary record layout. Saved analysis also accepts
legacy V1 socket state records, which contain fewer fields.

BPF hooks use `bpf_ktime_get_ns`. The collector samples realtime between
two monotonic readings and records the calibration and its sampling
uncertainty in the header. Clock steps or drift can increase the error in
estimated wall time. Conntrack events use monotonic time at userspace
receipt. Use monotonic timestamps to order observations within a capture.

BPF observers share a 256 KiB ring and a limit of 256 reservation attempts
per CPU per monotonic second. A per-CPU map stores one 48-byte counter value
per possible CPU, excluding kernel allocation overhead. The collector
reports failed reservations separately from deliberate rate limiting.
Timed and signal-driven stops detach the unpinned links before draining
the ring and reading the counters. The live viewer bounds recent event
data to 4,096 records or 2 MiB and reports history eviction as a gap.

## TCP lifecycle

| Hook | Observation and requirements |
|---|---|
| `sock:inet_sock_set_state` | Required TCP state tracepoint. CO-RE reads the tracepoint's socket pointer, protocol, and old/new state. |
| `tcp:tcp_retransmit_skb` | Optional TCP tracepoint. CO-RE reads the socket pointer, state, and retransmit return code. A recorded retransmit provides no loss location. |
| `fentry/inet_stream_connect`, `fexit/inet_stream_connect` | Optional BTF tracing hooks. Entry tracks timing by task in a 1,024-entry hash map. Exit reports the raw return code and, when the kernel supplied a valid IPv4/IPv6 sockaddr, the requested peer. Elapsed time measures the kernel call. For nonblocking connects, `-EINPROGRESS` describes work still in progress at return. |
| `fexit/inet_csk_accept` | Optional BTF tracing hook for the two-argument kernel signature. A non-null returned TCP socket identifies a successful dequeue at this hook. Later descriptor installation is outside its coverage. |

All four event types share the ring and rate limit described above. The V2 event
is 128 bytes, including IPv4/IPv6 address bytes and host-normalized ports,
socket network namespace inode, and the configured bound interface index when
available. CO-RE reads these fields from the hook's socket. An existing kernel
socket cookie is exposed when nonzero. The capture does not allocate a cookie,
and a namespace plus tuple can be reused. Timestamps use the clock calibration
described above.

When an optional TCP hook is unavailable or its attach fails, the capture
header records the affected probe and reason. If a combined load fails, retry
with `--state-only` to isolate the required tracepoint. Unpinned links are
released before the ring drains. Failed connect timing-map insertions are
counted separately, and unmatched results have no elapsed time. The BPF hot
path performs bounded lookups and copies; the shared rate limiter bounds event
volume while the timing map bounds in-flight connect tracking.

## Flow timelines and diagnoses

Analysis reads one saved JSONL capture and sorts events by monotonic timestamp,
using input line number to break ties. Evidence IDs refer to original input
lines, and each timeline includes the original event object. Flow IDs start
with the line number of the first event in monotonic order. Both ID types are
scoped to that file.

The correlator prefers the socket cookie scoped by namespace, then uses the
directional namespace and endpoint tuple. For tuple-based matches, a new
`CLOSE → SYN_SENT` starts a new flow and a gap over 120 seconds breaks the
association. An incomplete connect result can join a flow if its task,
namespace, requested peer, and measured call interval identify one matching
SYN start. Incomplete and ambiguous records can remain standalone. The
correlator keeps client and server socket perspectives separate. V1 captures
retain state observations but lack the metadata needed to join them.

Rules report observed establishment, refusal (`ECONNREFUSED`), timeout
(`ETIMEDOUT`), and retransmit hook activity. Each rule cites its evidence IDs.
An observed SYN without evidence of completion has an unknown outcome.
Capture loss, rate limiting, disabled probes, and incomplete metadata are
reported as gaps and reduce confidence in heuristic associations. Direct
observations keep their own confidence. The capture cannot locate packet loss
or distinguish application delay from network delay.

Offline analysis is bounded to 100,000 events, 64 MiB of input, and 16 KiB per
line. Malformed records fail with the input line number. Missing start or end
records are reported as capture gaps.

## Conntrack and NAT

The optional adapter subscribes to ctnetlink NEW, UPDATE, and DESTROY
multicast notifications in the capture process's namespace. It retains TCP
IPv4 and IPv6 records when the kernel reports NAT and the tuple changes.
Each record preserves the original and reply tuples, the conntrack namespace,
zones, ID when available, and source/destination NAT flags. Reversing the reply
tuple gives the translated tuple in the original direction. The adapter is
read-only and does not dump pre-existing entries. [Linux ctnetlink source](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_netlink.c)

The timestamp is userspace receipt time. `explain` associates a NEW record
only when the entire directional tuple matches exactly, the receipt falls
within the flow interval plus a one-second margin, and neither side has
competing candidates. This is a possible association, including across socket
namespaces. The kernel-reported translation has its own evidence and confidence.
There is no packet identity or automatic merge of flows across NAT.

The adapter requests a bounded socket receive queue, reads at most 16
datagrams per polling cycle into a reusable 64 KiB buffer, and emits up to
512 records per second. Capture end reports overflow notifications, truncated
datagrams, decode errors, and its separate rate-limit count. Closing the file
descriptor releases the subscription. If the optional subscription cannot be
opened, a normal capture remains available with `--conntrack` omitted.

## TC ingress and egress

`--tc-interface` loads `tcx/ingress` and `tcx/egress` on one interface in the
capture process's network namespace. The selected device is resolved to an
ifindex before loading. Both programs return `TCX_NEXT` on every path, and the
loader creates no qdiscs or legacy filters. Dropping the unpinned link FDs
detaches both programs before draining the ring. If TCX is unavailable, a
normal socket capture remains available. [Linux TCX link implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/tcx.c)

The BPF programs read fixed-size headers relative to the skb network header
and emit the timestamp, namespace, ifindex, direction, directional TCP
endpoints, low eight TCP flag bits, and skb length. IPv4 fragments, IPv6
extension headers, unsupported encapsulation, and short headers are skipped.
The probe performs bounded reads and shares the socket-event ring and
per-CPU rate limit. A busy interface can therefore reduce socket-event
coverage. The summary includes aggregate ring and rate-limit counters.

TC observations describe skbs at the selected hook. Offloads, cloning, and
recirculation can affect what is observed, and earlier classifiers may affect
whether the hook is reached. An skb length is not necessarily an on-wire
packet length. Flow reports associate exact directional tuples within the
same namespace and within 250 ms of the flow's observed interval. Reports
withhold those associations when another matching flow has an overlapping
window. Receipt at a hook gives no proof of delivery or loss location.

## Bridge forwarding

`--bridge-interface` enables the `fentry/__br_forward` probe. On Kali the hook
uses split BTF from the loaded bridge module. CO-RE reads the bridge and output
port from the selected bridge port, and the ingress device from the skb at
function entry. The namespace and bridge ifindex restrict capture to the
selected bridge. Locally originated frames have no ingress port in the
record. [Linux bridge forwarding source](https://github.com/torvalds/linux/blob/master/net/bridge/br_forward.c)

The probe reads one fixed-size Ethernet header and emits the port indices,
MAC addresses, outer EtherType, skb length, and monotonic timestamp. It skips
frames with an unreadable Ethernet header. It does not read payloads, change
forwarding, or infer a socket identity from MAC addresses. Software port
selection may be recorded for multiple copies of a flooded frame. Hardware
offload and paths that bypass the hook are outside coverage.

Bridge events share the bounded BPF ring and per-CPU rate limit. The
unpinned link detaches before the ring drains. If bridge BTF or tracing
support is unavailable, omit `--bridge-interface` to run a socket capture.

## IP forwarding

`--routing` enables `fentry/ip_forward` and `fentry/ip6_forward` when their
signatures are present in kernel BTF. CO-RE resolves the input device and
namespace from the skb and the output device from its attached destination
entry. The observer reads a fixed-size base IP header and records both
addresses, both ifindices, namespace, IP protocol or IPv6 base next-header
number, TTL or hop limit, and skb length. It skips an observation if either
device or the base header is unavailable. [IPv4 forwarding](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/ip_forward.c) · [IPv6 forwarding](https://github.com/torvalds/linux/blob/v6.18/net/ipv6/ip6_output.c)

These are forwarded-traffic observations from the capture process's network
namespace. They describe the route at entry, before the forwarding path's
TTL or hop-limit decrement and subsequent policy. They do not cover
forwarding lookups that fail before reaching these hooks, local traffic, or
later rerouting or delivery. Linux can reuse an attached destination across
packets, and the records carry no unique packet identity.

The probes filter by ingress namespace before reading the route and header.
They share the bounded BPF ring and per-CPU rate limit. Capture closes the
unpinned links before draining the ring. `doctor` reports which BTF signatures
are present, and capture reports disabled hooks. Omit `--routing` if the
forwarding probes cannot load.

## Coverage and operational limits

lnfr records headers and metadata, including information that can identify
hosts and workloads. Capture writes to stdout. Saved files and retention
are managed by the caller. The probes leave packets and forwarding
decisions untouched.

The capture observes specific hooks on one Linux host. Packet payloads,
local drop reasons, and the complete path of a packet are outside its
coverage. Cloning, offload, recirculation, tuple reuse, and missing records
can make associations ambiguous. A missing event leaves the activity
unobserved. See the [user guide](USER_GUIDE.md#troubleshoot-capture-and-coverage)
for privilege and coverage checks and [verification](TEST_PLAN.md) for
reproducible fixture and overhead measurement commands.
