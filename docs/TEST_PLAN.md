# Test strategy

All fault-injection tests run **inside disposable network namespaces** and must clean up interfaces, namespaces, and qdisc state. Do not alter host networking/firewall configurations.

## Phase 1 ring-buffer smoke test

Run on `kali-z570` as a normal user. Elevate only the integration fixture, which
needs to create disposable namespaces and load and attach the BPF program.

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
sudo bash scripts/test-phase1.sh
```

The fixture creates two namespaces linked by a veth pair, waits for the capture
to attach, and makes a real IPv4 TCP connection. It checks the client's
`CLOSE → SYN_SENT` observation, ring-buffer delivery and loss counters, and
clean completion on SIGINT and timeout. It prints the matching observation and
capture summary on success. A kernel without the required hook, BTF, or
privileges cannot run this fixture.

## Phase 2 TCP veth fixtures

Build as your normal user, then run the namespace fixtures on `kali-z570`.
They require Python 3, iproute2 (`ip`, `ss`, `tc`), tcpdump, and the
kernel's `netem` qdisc.

```bash
cargo build --locked
target/debug/nfr doctor
sudo bash scripts/test-phase1.sh
sudo python3 scripts/test-phase2.py
```

Phase 2 uses namespace-filtered captures for the client and server. N1 checks a
successful IPv4 connection, accepted socket, and state transitions against
`ss`. N2 checks the connect return code against the client's `ECONNREFUSED`
and a TCP RST in tcpdump. N3 temporarily drops traffic with netem on the
server's veth egress, checks the client's retransmission against repeated SYNs
in tcpdump and the qdisc's drop counter, then removes netem and checks recovery.
N8 checks IPv6 connect and accept tuples. On success, the fixture prints
matching observations and both capture summaries. It deletes the temporary
namespaces and fixture output on exit.

Verified on `kali-z570` with kernel `6.18.9+kali-amd64`. The fixture observed
an IPv4 connect and accept with matching endpoints, `-111` (`ECONNREFUSED`)
for the closed port, a client SYN retransmit under netem, and IPv6 connect
and accept. The client and server received 23 and 24 events respectively.
Both captures exited on SIGINT and reported zero ring loss, rate limiting,
and connect-tracking loss. The fixture printed:

```text
PASS: N1 TCP lifecycle, N2 refusal, N3 retransmission, N8 IPv6
```

## Phase 3 flow and diagnosis verification

The veth fixture above now also runs N4, a blocking connect through sustained
netem loss. It checks the client's `ETIMEDOUT` against the kernel connect event.
The fixture runs `nfr flows` and `nfr explain` on both captures and checks that
each expected diagnosis cites its exact original event. It also checks that
timeline events are ordered by monotonic timestamp and retransmit reports
retain uncertainty about the cause.

Verified on `kali-z570`. The client and server captures received 28 and 26
events, respectively, with zero ring loss, rate-limited events, or connect
tracking loss. In N4 the kernel reported `-110` (`ETIMEDOUT`) after about
3.06 seconds. The fixture printed:

```text
PASS: N1 TCP lifecycle, N2 refusal, N3 retransmission, N4 timeout, N8 IPv6, and Phase 3 evidence
```

Rust tests cover out-of-order input, reuse of a tuple across connection
attempts, namespace separation, incomplete capture metadata, a refusal whose
socket ports were cleared, and unresolved attempts. They distinguish kernel
timeout evidence from a connection whose outcome was simply unobserved.

An offline replay of three events from the verified Phase 2 fixture produced
the following refusal diagnosis. The line number refers to the replay excerpt.

```json
{"code":"connection_refused","confidence":"confirmed","observation":"The kernel connect call returned ECONNREFUSED.","alternatives":["The capture does not identify what generated the refusal."],"evidence_ids":["line-2"]}
```

## Phase 4 NAT veth fixture

```bash
cargo build --locked
sudo python3 scripts/test-phase4-nat.py
```

N5 creates a client, router, and server with two veth links. Only the router
namespace enables IPv4 forwarding and applies the temporary nftables DNAT and
SNAT rules. The fixture uses `nsenter --net` for the capture processes so they
can subscribe in the router namespace while retaining the host tracefs mount.
It checks the original and translated SYN tuples against
tcpdump on both links and confirms that the application endpoints agree. Each
socket flow report must cite the corresponding conntrack NEW record. The
fixture exercises IPv4 on Kali. Rust tests cover IPv6 parsing and ambiguous
association handling.

Verified on `kali-z570`. Conntrack evidence `line-5` showed the original
`192.0.2.2:36291 → 203.0.113.9:8443` translated to
`198.51.100.1:40000 → 198.51.100.2:47327`. The fixture verified both tuples
against tcpdump and verified the evidence association in both socket reports.

```text
PASS: N5 DNAT and SNAT tuples match both veth links and both socket perspectives
```

## Phase 4 TC veth fixture

```bash
cargo build --locked
sudo bash scripts/test-phase4-tc.sh
```

The fixture attaches both TCX probes to the client veth in a disposable
namespace. It checks the egress SYN and ingress SYN-ACK against tcpdump,
verifies evidence in the socket-flow report, and checks the qdisc and attached
program state after capture. Rust tests cover binary decoding and tuple
association, including overlapping flow windows.

Verified on `kali-z570`. Evidence `line-3` recorded the egress SYN from
`192.0.2.1:51452` to `192.0.2.2:55265`. Evidence `line-4` recorded the
reverse ingress SYN-ACK on the same veth. Both matched tcpdump and appeared in
the socket-flow report. The fixture verified that the qdisc stayed unchanged
and the attached program state returned to its baseline.

```text
PASS: TCX ingress and egress match tcpdump, flow evidence, and clean detach
```

## Phase 4 bridge veth fixture

```bash
cargo build --locked
sudo bash scripts/test-phase4-bridge.sh
```

The fixture creates a Linux bridge with two veth ports in a disposable
namespace. A TCP handshake crosses the bridge between two isolated endpoint
namespaces. Tcpdump on both ports and the learned FDB provide independent
checks for both directions. The fixture also verifies that the bridge program
is released after capture. Rust tests cover bridge record decoding and its
coexistence with socket events in saved captures.

Verified on `kali-z570`. Evidence `line-5` recorded IPv4 forwarding from
port ifindex 3 to ifindex 4. Evidence `line-6` recorded the reverse direction.
Both observations matched tcpdump and the learned FDB, and the probe detached
after capture.

```text
PASS: bridge forwarding matches both veth links, learned FDB entries, and clean detach
```

## Phase 4 routed veth fixture

```bash
cargo build --locked
sudo bash scripts/test-phase4-routing.sh
```

The fixture creates a client, router, and server with two routed veth links.
It enables IPv4 and IPv6 forwarding only in the router namespace. The fixture
compares the observed output interfaces against `ip route get` and uses
tcpdump on both links to confirm that both handshakes crossed the router.
It checks the known client TTL and hop limit, both forwarding directions,
zero reported ring loss and rate limiting, and clean detach.

Verified on `kali-z570`. IPv4 evidence `line-3` and IPv6 evidence `line-15`
both recorded ingress ifindex 2 and selected egress ifindex 3. The observed
IPv4 TTL was 48 and the IPv6 hop limit was 52, matching the fixture's client
settings. Both routing hooks detached after capture.

```text
PASS: IPv4 and IPv6 forwarding match ip route get, tcpdump, and clean detach
```

## Phase 5 terminal UI

To browse a verified client capture from the veth fixture:

```bash
cargo build --locked
nfr_veth_capture=$(mktemp /tmp/nfr-veth.XXXXXX.jsonl)
sudo python3 scripts/test-phase2.py --emit-client-jsonl >"$nfr_veth_capture"
target/debug/nfr tui --input "$nfr_veth_capture"
```

Select a flow, move to its timeline, and inspect an event. Check that **d**
shows the same diagnosis and evidence IDs as `nfr explain` for that flow.
Check **c** for capture coverage and **q** for a clean return to the shell.
Ratatui test-backend checks also exercise resizing, empty captures,
selection, and detail views without privileges.

The terminal smoke test used a saved JSONL excerpt of the verified Phase 3
client capture. It navigated to the refusal, displayed its
`ECONNREFUSED` evidence and the excerpt's coverage gaps, and restored the
terminal on exit.

```text
PASS: 126×36 flow table, refusal evidence, coverage, and terminal restoration
PASS: 78×32 flow table, refusal evidence, coverage, and terminal restoration
```

### Live terminal mode

```bash
cargo build --locked
sudo -v
target/debug/nfr tui --live
```

From another terminal, make a TCP connection, for example
`curl --max-time 2 http://127.0.0.1:1`. Confirm that the flow and evidence
appear without reloading. Move into the timeline while generating more
connections and confirm that the selected event stays in view. Press **f**
to follow the latest flow again and **q** to stop the collector and restore
the terminal. Unit tests cover rolling history, selection across updates,
and collector shutdown through its control pipe.

## Baseline tools

`iproute2`, `ping`, `curl`, `ss`, `tcpdump`, `tc`, `nstat`, `bpftool`, optionally `conntrack`, `iperf3`, Python stdlib for controlled TCP servers.

## Matrix

| ID | Test | Ground truth | Expected NFR behavior |
|---|---|---|---|
| N1 | veth TCP handshake + data | tcpdump + socket outcomes | Flow identified; state timeline, interface and tuple accurate |
| N2 | no listener (TCP RST/refused) | client errno, tcpdump RST | Classify refusal if direct evidence; no "packet dropped" claim |
| N3 | controlled packet loss via `tc netem` inside namespace | netem stats + tcpdump | Retransmissions observed where hook supports; state loss location not inferred without evidence |
| N4 | one-way blackhole using namespaced nftables/drop | nft counters + tcpdump | timeout / no response; drop location only if direct hook evidence |
| N5 | NAT using two or three namespaces | conntrack + tcpdump both sides | original/translated tuple correlation with confidence and limitations |
| N6 | bridge forwarding across veth pair(s) | bridge FDB + tcpdump | report observed bridge/TC hooks; tolerate missing stages |
| N7 | parallel same-destination flows | separate socket cookies and port pairs | distinct flow identities; no accidental merging |
| N8 | IPv6 | tcpdump + ss | correctly encoded/decoded addresses or explicit unsupported note |
| N9 | high event rate | load generator and map counters | bounded memory, loss counters rise if overloaded, no deadlock |
| N10 | unsupported hook / insufficient permissions | `doctor` + test host | readable diagnostic, clean exit, no misleading diagnosis |

## Performance acceptance metrics

Establish and record baseline, do not invent target numbers before measuring: packet rate, TCP throughput, p50/p95/p99 latency, CPU utilization, memory, ringbuf loss, map fill ratio. Compare idle and loaded capture; adjust sampling/filters to meet operational budget. First correctness, then optimize.

## Confidence tests

- Without local drop event, never report `confirmed local kernel drop`.
- With only retransmission evidence, report `retransmission observed`, not `firewall blocked packet`.
- Missing probe or ringbuffer loss degrades certainty and adds warning.
- A flow crossing NAT cannot be joined solely on post-NAT tuple.
- GSO/GRO/cloned buffers must not be presented as one-to-one packet observations.
