# macOS RustRover -> kali-z570 (Kali Linux)

## Architecture

macOS is the visual front-end. Kali is the only build, test, run, BPF loader and kernel tracing environment. Keep repository on Kali (`~/src/network-flight-recorder`), not on the Mac-mounted network filesystem, for file-watcher/toolchain consistency.

## SSH verification

On macOS:

```bash
ssh -G kali-z570 | grep -E '^(hostname|user|identityfile|forwardagent) '
ssh kali-z570 'hostname; uname -a; uname -m; id'
```

If `kali-z570` is not configured on macOS, put the host into `~/.ssh/config` with Kali IP/user and a **Mac-local SSH key**; install its public key in Kali `~/.ssh/authorized_keys`. Prefer `ForwardAgent no` unless a specific workflow needs it. Do not copy a Windows private SSH key if a new Mac key can be created instead.

## RustRover modes

- **Preferred:** RustRover Remote Development / JetBrains Gateway via SSH if supported by the installed product/version. Backend indexes/builds on Kali; Mac shows JetBrains Client UI. Verify supported OS/CPU/runtime requirements before adopting.
- **Fallback:** local RustRover on macOS with Git push/pull and SSH terminal commands (`ssh kali-z570 'cd ~/src/... && cargo test'`), then GDB remote debugging of Linux userspace binaries if configured. Do not claim the Mac local debugger can debug eBPF kernel instructions.
- **Third option:** VS Code Remote-SSH if RustRover remote capability is unavailable or unsuitable.

## Baseline checks on Kali

```bash
uname -r; uname -m
ls -l /sys/kernel/btf/vmlinux
command -v clang; command -v bpftool; command -v rustc; command -v cargo
ls /sys/kernel/tracing/events/tcp 2>/dev/null || true
ls /sys/kernel/tracing/events/skb 2>/dev/null || true
sudo bpftool feature probe kernel  # only after confirming sudo access
```

Avoid automatically running `apt upgrade`, changing the kernel or adjusting security settings. Kali is rolling and may change available BPF hooks with kernel upgrades; capture toolchain/kernel versions for reproducibility.

## Permissions and security

Loading and attaching different eBPF programs may require privilege; requirements vary by kernel and hook. Run only a narrowly scoped loader/test command with `sudo` during early development if necessary. Do not run JetBrains backend/Codex as root. `sudo bpftool ...` should be invoked manually after reviewing commands. Always detach probes on exit. Protect SSH access (keys, host verification) and do not expose arbitrary debug ports publicly.

## Remote breakpoints

- Rust userspace: standard GDB or LLDB debugging in remote IDE; debug symbols enabled.
- Kernel BPF: verifier logs, trace pipe carefully, BPF ring buffer events, bpftool inspection, BPF test-run where supported, deterministic namespace fixtures. Ordinary userspace step-debugging does not directly apply.

## Host limitations

- Kali is x86_64 only if `uname -m` confirms it.
- Wi-Fi may not support native XDP; use virtual `veth` for reproducible tests, then Ethernet on suitable driver if native-XDP benchmarking is needed.
- Observe network namespaces explicitly; the host can run eBPF probes but their visibility depends on attachment scope/hook.
