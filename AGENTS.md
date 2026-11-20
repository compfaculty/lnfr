# AGENTS.md — Codex project contract

You are an engineering agent working on **Linux Network Flight Recorder** (NFR). Read `README.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/REMOTE_DEV.md`, and `docs/TEST_PLAN.md` before changes.

## Environment and tooling
- macOS is the developer's visual workstation; **all actual eBPF compilation, execution and tests take place on x86_64 Kali Linux host `kali-z570`**.
- Do not assume Linux capabilities, kernel version, BTF support, hook existence, or NIC native-XDP support. Inspect via preflight and probe; record exact versions.
- Implement kernel programs in **C + libbpf/CO-RE** and userspace in **Rust + libbpf-rs**. Prefer `libbpf-cargo` for skeleton generation if compatible with the detected toolchain.
- Do not run the IDE/backend as root. Keep privilege requirements local to the loader/test invocation.

## Workflow
1. Work on one roadmap milestone or one scoped task at a time. First report a concise implementation plan with modified files, dependencies and test strategy.
2. Keep a runnable main branch. Add small, independently reviewable commits; do not refactor unrelated code.
3. For every kernel probe: name attach point, required kernel support, field extraction method, performance implications, detach cleanup, and fallback.
4. Separate **observations** (hook-fired events/counters) from **inferences** (hypothesized cause). Never claim that absence of an event proves a network stage did not execute.
5. Use monotonic kernel timestamps (`bpf_ktime_get_ns`) for kernel event order; userspace maps to wall-clock with calibration and explicit error/uncertainty.
6. Avoid logging payloads, credentials or arbitrary user memory. Default to minimal headers/metadata, sampling, rate limiting and short retention.
7. Bound map sizes, event volume, memory and CPU use. Report ring buffer loss/drop counters and instrument overhead.
8. Include deterministic tests with Linux network namespaces and veth interfaces, then clearly mark host-specific tests.
9. Every change must run `cargo fmt --check`, `cargo clippy` (appropriate flags), Rust unit tests, build of BPF object(s), verifier/load smoke test if privileges permit, and relevant integration tests. Report if a check could not be performed.
10. Never silently install, upgrade, alter boot configuration/kernel, change firewall/network interface state, or enable persistent services. Ask for approval before changing host configuration. Test-netns changes are allowed only within namespaced fixtures and must clean up.

## Scope guardrails
- Phase 1 is **socket/TCP flow diagnosis**, not full kernel-path reconstruction.
- `kfree_skb` reason/context coverage is kernel-dependent. Drops in drivers, hardware, external network and other machines are outside local guaranteed visibility.
- NAT/conntrack/bridge/routing correlation is opportunistic, not a universal unique per-packet ID. Explicitly handle clones, GSO/GRO, recirculation, transformations, missing hooks and map eviction.
- eBPF verifier success does not mean semantics are correct. Validate against `ss`, `ip`, `tcpdump`, `nstat`, `tc`, `conntrack` where available.
- Do not modify/drop packets. No auto-remediation in MVP.

## Definition of Done for every task
- Code + tests + documentation + reproducible commands.
- Example output captured from real test fixture (not invented).
- Error conditions, permission failures, unsupported hooks and lost-events behavior documented.
- Performance/memory implications noted; no unbounded hot-path allocations.
