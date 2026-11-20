# Codex task prompts

Use **one prompt per iteration**. Always include `AGENTS.md` in context and require a concise plan before changes.

## Task 0 — Inventory and implementation proposal

> Read AGENTS.md and all docs. We develop on macOS with RustRover, but build/run/test exclusively on x86_64 Kali host `kali-z570`. Do not assume kernel capabilities. Review preflight output that I provide. Propose the exact repository layout, dependency versions compatible with the host, phase-1 BPF attach point, commands for reproducing the build, privilege boundary, and tests. DO NOT modify the host or implement features yet. List blockers and ask only for essential missing facts.

## Task 1 — Minimal skeleton

> Implement Phase 1 only: a reproducible Rust Cargo + C/libbpf CO-RE program skeleton, one available kernel tracepoint, bounded ring buffer, versioned event schema, Rust loader and `nfr doctor`/`nfr capture --duration`. Ensure clean Ctrl+C detach. Add build instructions, tests, and run the checks allowed on this host. No network-path claims yet. Report unsupported capabilities clearly.

## Task 2 — TCP MVP

> Implement Phase 2 for TCP lifecycle events and retransmission observations using only hooks confirmed present by `nfr doctor`. Track socket/flow identity and IPv4/IPv6; bounded maps; event loss. Add reproducible veth-netns fixtures N1, N2, N3 and verify output against tcpdump/ss. Never state network loss location without evidence. Provide real captured output and test results.

## Task 3 — Evidence-driven diagnosis

> Implement Phase 3: correlate events into flow timelines and emit a structured explanation with evidence IDs, confidence, alternatives and blind spots. Define deterministic rules for RST/refusal, observed retransmits, observed local drops, timeouts and insufficient evidence. Add negative tests ensuring no hallucinated cause. Retain raw events as JSONL.

## Task 4 — Conntrack and NAT (separate PR)

> First inspect supported conntrack/netfilter hooks and BTF. Propose a minimal adapter with original/reply tuples and feature gating, then implement only this adapter with N5 namespace fixtures. Correlate with existing flow events using explicit confidence; account for missing events and tuple changes. Do not modify production firewall state.

## Task 5 — TC/bridge/routing (separate PRs)

> Implement one selected stage family per PR. Include probe capability checks, fixtures, event schema changes, overhead measurements, actual output and documented blind spots. Do not claim a universal per-packet unique identity.

## Task 6 — TUI

> Implement Ratatui-based flow table and per-flow evidence timeline. Read persisted JSONL and optional live stream; show source hook, timestamps, evidence, uncertainty, disabled probes and lost-event warnings. Do not add UI-only data fabrications.

## Task 7 — Optional AI summarization

> Add opt-in AI summary adapter that takes deterministic diagnostic report and evidence IDs only; require citations to actual IDs, redact private fields by default, compare model statements to available evidence, and fall back to deterministic reporting when AI is off/unavailable.
