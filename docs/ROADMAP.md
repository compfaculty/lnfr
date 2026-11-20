# Delivery roadmap

No fixed calendar promises; move to the next phase only after acceptance criteria pass.

| Phase | Goal | Exit condition |
|---|---|---|
| 0 — Environment | Inventory actual Kali kernel, toolchain, BTF, permissions, remote IDE workflow | `nfr doctor` design + preflight log; minimal BPF load/attach/detach smoke works or documented blocker |
| 1 — Skeleton | Cargo workspace, reproducible builds, libbpf-rs pipeline, CI-like local checks | One tracepoint event observed with versioned schema and clean cancellation |
| 2 — TCP MVP | Connect/accept/state/retransmit and selected local drop events | Namespace fixture yields documented flow timeline and bounded loss counters |
| 3 — Correlation | Flow IDs, socket identities, tuple normalization, deterministic diagnosis | Validated reports for success, connection refused, simulated loss, timeout; no unsupported certainty |
| 4 — Network path | Selectively add netfilter/conntrack/NAT, TC, bridge, route context | Each subsystem independently feature-gated; NAT + veth + bridge tests pass on supported kernel |
| 5 — TUI/export | Live flow table, timeline, diagnostic evidence, JSONL + optional pcap linkage | User can inspect flow and show precise evidence and blind spots |
| 6 — Quality | Performance profiling, kernel matrix, packaging, documentation | No crashes/leaks, bounded overhead, installer-less reproducible setup |
| 7 — Optional AI | Summarize evidence through local/remote LLM with provenance | AI text cites event IDs; no unsupported statements; works with AI disabled |

## Milestones with detail

### Phase 0 — Remote and kernel feasibility
- SSH from Mac to `kali-z570`; verify machine identity and arch (`uname -m` should be x86_64).
- Check CPU/RAM/disk, Linux kernel, BTF, `bpftool feature probe` and whether required tracepoints are present.
- Identify installation prerequisites (`clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `pkg-config`, Rust toolchain); propose changes before installing.
- Decide RustRover SSH full-remote vs local IDE + remote build based on actual installed version/capabilities. Do not assume local macOS build is valid for Linux target.
- Record baseline kernel config, capabilities, and known blind spots.

### Phase 1 — Functional telemetry pipeline
- Build.rs or libbpf-cargo generates skeleton from one minimal C BPF program.
- Userspace loader attaches, polls events and detaches on Ctrl+C; no resource leaks.
- Schema V1: monotonic timestamp, event kind, CPU, PID, contextual IDs.
- Unit test schema encoding, failed attach handling and endianness.

### Phase 2 — TCP diagnostics MVP
- Trace TCP connect outcomes, state transitions, retransmits using hooks available on Kali; include full IPv4 and IPv6 handling or explicitly gate unsupported family.
- Show src/dst tuple, PID, netns, connect latency where supported, retransmission count, close reason/errno when observable.
- Capture actual local skb drop reasons when supported and mark coverage limitations.
- Always expose lost event counters.

### Phase 3 — Cause analysis
- Deterministic diagnostic rules: refused (RST/errno evidence), retransmission observed, local skb drop reason, no response within capture window, app delay vs network delay where separable.
- Failure classification includes `insufficient evidence` and an explicit `unknown` state.
- Tests prove model does not infer where external packet loss occurred.

### Phase 4 — Path-specific adapters
- Add tracing family-by-family, with tests and feature detection: 1) routing context and interface changes; 2) conntrack/NAT; 3) bridge + veth; 4) TC ingress/egress.
- Track original and translated tuples; handle cloned skb and GSO/GRO ambiguity.
- Avoid promising complete order across hooks without evidence.

### Phase 5 — Experience
- `nfr capture`, `nfr flows`, `nfr explain`, `nfr doctor`; explicit `--filter` and duration options.
- Ratatui timeline (not required before CLI is stable); JSONL export, optional import of tcpdump/pcap metadata for cross-checking.

### Phase 6 — Robustness
- Load/performance tests with large event volumes; memory limit, CPU utilization and event-loss counters.
- Test supported different kernel versions where practical, use runtime fallback for missing hooks.
- Document threat model and capture privacy.

### Phase 7 — AI integration (opt-in)
- Provide only structured evidence, metadata and diagnostics to model; redact by default.
- Every explanation references event IDs and states alternatives; fail closed to deterministic report if no AI service.

## Out of scope until Phase 7
Packet payload inspection, TLS decryption, active firewalling, policy enforcement, full packet replay, production multi-node correlation, deterministic tracing of every packet's kernel path, and automatic system changes.
