# Roadmap

## Available today

| Area | Delivered |
| --- | --- |
| Host and capture | `doctor` checks candidate hooks. `capture` emits bounded JSONL with probe coverage and loss counters. |
| TCP lifecycle | IPv4 and IPv6 state changes, connect results, successful kernel accepts, and retransmits on supported kernels. |
| Flow diagnosis | Monotonic timelines and evidence for observed establishment, refusal, timeout, and retransmission. |
| Network context | Optional conntrack NAT, TCX ingress and egress, software bridge, and IP forwarding observations. |
| Terminal workflows | A live TCP view and saved-capture browsing with flow, event, diagnosis, and coverage panes. |

See the [user guide](USER_GUIDE.md) for usage and the [test plan](TEST_PLAN.md)
for fixture results and kernel-specific checks.

## Current focus

- Measure CPU, memory, latency, and capture loss under reproducible workloads.
  Compare the workload by itself, with capture, and with the live viewer.
- Verify behavior across kernels, including clear diagnostics when hooks or
  permissions are unavailable.
- Improve setup and packaging for people running lnfr outside the development host.

## Possible extensions

- Record local drop reasons on kernels with compatible `skb:kfree_skb`
  metadata. Verify each report against a controlled local drop.
- Explore correlation with packet-capture metadata and richer TCP or
  queueing metrics. Keep association windows and resource usage bounded.
- Evaluate opt-in summaries grounded in existing evidence IDs, with
  deterministic reports available independently.

The project focuses on passive diagnosis. Packet payload capture, traffic
enforcement, automatic system changes, and deterministic tracing of every
packet across machines are outside that scope.
