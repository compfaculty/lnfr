# Architecture and instrumentation strategy

## System layout

```text
macOS / RustRover or JetBrains Client
             │ SSH (private network)
             ▼
kali-z570 (Linux x86_64)
  ├── cargo workspace
  │   ├── crates/nfr-common     (schema, IDs, error types)
  │   ├── crates/nfr-agent      (loader, ring buffer, event pipeline)
  │   ├── crates/nfr-core       (correlator, flow state, evidence)
  │   ├── crates/nfr-cli        (capture, inspect, doctor, export)
  │   ├── crates/nfr-tui        (later; Ratatui)
  │   └── bpf/                  (C + CO-RE, libbpf skeleton)
  ├── Linux BPF verifier + maps + ring buffer
  ├── Linux kernel socket/TCP/skb/netfilter/TC hooks
  └── network namespace fixtures
```

Start with one executable CLI (`nfr`) and separate library crates only when interfaces are stable. Avoid premature microservice architecture.

## Instrumentation phases

1. **MVP:** socket connect/accept lifecycle (where hooks supported), TCP state transitions, retransmits, skb drop reasons, TCP/IP metadata. Prefer stable tracepoints; selectively use fentry/fexit (BTF) or kprobes with explicit kernel-version checks. Record PID/TGID, netns, cgroup, socket cookie where available, 5-tuple, interface index, timestamps. Beware not every event has all identifiers.
2. **Networking:** netfilter hooks / conntrack events and NAT original/reply tuples, TC ingress/egress metadata, bridge forwarding, route-relevant tracepoints. Implement isolated adapters per hook family. Avoid kernel-private structure assumptions; use CO-RE and graceful feature gating.
3. **Advanced:** optional packet-path mode for *selected* flows, QoS queueing, detailed TCP RTT/RTO/cwnd metrics, VRF/veth/VXLAN and containers. High-overhead features must be opt-in.

## Event schema (versioned)

```text
EventHeader { schema_version, kind, monotonic_ns, cpu, source_id, flags }
FlowIdentity { netns_cookie?, socket_cookie?, pid_tgid?, cgroup_id?,
               l3_proto?, l4_proto?, src_ip?, src_port?, dst_ip?, dst_port?,
               ifindex?, direction? }
Observation { hook, action, kernel_reason?, tcp_state?, skb_len?,
              conntrack_zone?, observed_tuple?, original_tuple?,
              data_quality, payload_specific }
```

`?` means field can be absent. Identifiers are scoped and may change across NAT or skb clones. Version event schema and BPF/userspace compatibility. Endianness and IPv4/IPv6 representation must be specified and tested.

## Correlation and evidence

- **Flow-level correlation:** prefer socket cookie + netns; supplement with 5-tuple, process/cgroup, time window; preserve NAT tuple transformations and confidence.
- **Packet-level correlation:** optional bounded skb pointer/identity within a short observational window; pointer reuse and cloning invalidate global uniqueness. A 5-tuple is *not* a packet identifier. TCP sequence/ACK plus timestamps can help but are imperfect under GSO/GRO and retransmission.
- **Drop observability:** `skb:kfree_skb` or comparable hooks if supported. A drop event is evidence of a local kernel drop, not necessarily the root cause. Not all drops are observed through this hook.
- **Negative evidence:** absence of downstream event must produce `unknown/not observed`, not `dropped here`.
- **Explanations:** deterministic rules first, with evidence IDs, timestamps, alternate hypotheses and confidence (confirmed / probable / possible / unknown). AI explanation is optional and cannot create new evidence.

## Data pipeline

BPF hooks -> bounded maps / ring buffer -> Rust collector -> normalization -> bounded correlator -> JSONL (optional SQLite later) -> CLI/TUI report.

Report ringbuf reservation failures / lost events through BPF map counters. Include feature availability and sampling rates with every capture session. Capture may be partial or biased under load. Use timeout and cancellation-safe cleanup.

### Phase 1 baseline

The sole attach point is `sock:inet_sock_set_state`. CO-RE relocates the
tracepoint's `protocol`, `family`, `oldstate`, and `newstate` fields against kernel
BTF. The probe filters for TCP and records state transitions, CPU, and the
current task's TGID, TID, and cgroup ID. The payload is a fixed 40-byte V1
little-endian record. It contains no socket addresses, kernel pointers, or
packet payloads. There is no alternate attach point for this phase.

The probe caps reservation attempts at 256 per CPU per monotonic second. The
ring has a fixed 256 KiB capacity, and the counter array uses one 40-byte value
per possible CPU, excluding kernel allocation overhead. Rust decodes one
sample at a time and writes it to stdout. Rate-limited events and failed ring
reservations are counted separately. The summary reports userspace receipt and
elapsed time. CPU and latency overhead have yet to be measured.

Kernel timestamps come from `bpf_ktime_get_ns`; use them to order observations.
Estimated wall time uses a realtime sample bracketed by two monotonic readings.
The capture header carries that calibration and its sampling uncertainty.
Wall-clock steps or drift during capture can add error beyond that uncertainty.
At timeout or on SIGINT/SIGTERM, userspace releases the unpinned link before
draining the ring and reading counters.

### Phase 2 TCP lifecycle

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
and a namespace plus tuple can be reused. Wall and monotonic timestamps retain
the Phase 1 semantics.

When optional metadata is absent or an optional attach fails, the capture
header records the affected probe and reason. If a combined load fails, retry
with `--state-only` to isolate the required tracepoint. Unpinned links are
released before the ring drains. Failed connect timing-map insertions are
counted separately, and unmatched results have no elapsed time. The BPF hot
path performs bounded lookups and copies; the shared rate limiter bounds event
volume while the timing map bounds in-flight connect tracking. CPU and latency
overhead have yet to be measured.

Phase 2 observes connection lifecycle and retransmits. It has no local drop
probe and draws no conclusions about where packets were lost.

### Phase 3 flow timelines and diagnoses

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

### Phase 4 conntrack and NAT

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

### Phase 4 TC ingress and egress

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

### Phase 4 bridge forwarding

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

### Phase 4 routing

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

## Security and operational limits

- Default read-only observation; no packet capture payload, packet mutation or enforcement.
- Root/CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN requirements vary with kernel and hook; discover rather than assuming a universal capability set.
- Do not set permanent unrestricted capabilities or disable host security mechanisms for convenience.
- Bound event rate, ring buffer, per-flow state count and retention. Allow filters by PID, netns, interface, cgroup and tuple.
- Default no remote telemetry; local files only, redact source/destination addresses in exports when requested.

## Initial CLI UX

```bash
nfr doctor
nfr capture --duration 30s --tcp --output session.jsonl
nfr flows --input session.jsonl
nfr explain --input session.jsonl --flow <flow-id>
```

`doctor` prints hook support and privileges. `capture` must not imply all stages are covered; print `active-probes` and `blind-spots`.
