# Contributing and remote development

Build and test as a normal user on x86-64 Linux. The project's reference
environment is the Kali host `kali-z570`. Maintainers working from macOS use
it for compilation, BPF loading, and integration tests. Keep the checkout
and toolchain on the Linux host when using a remote IDE.

## Set up the development host

See the [build prerequisites](USER_GUIDE.md#build-and-check-your-host) and run
the read-only inventory from the repository root.

```bash
bash scripts/preflight.sh
cargo build --locked
target/debug/nfr doctor
```

Record the kernel, architecture, and toolchain versions when reporting a
build or attach issue. Hook availability depends on the running kernel,
its BTF, loaded modules, and the process's permissions. Review any host
configuration changes with the maintainer before making them.

### Connect from macOS

Verify the SSH configuration and check the target before opening an IDE
session.

```bash
ssh -G kali-z570 | grep -E '^(hostname|user|identityfile|forwardagent) '
ssh kali-z570 'hostname; uname -r; uname -m; id'
```

Use RustRover Remote Development over SSH if supported by your setup.
Alternatively, edit locally and build in a separate Linux checkout over
SSH. Use a workstation-local SSH key and keep agent forwarding disabled
unless the workflow requires it.

## Verify changes

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
sudo bash scripts/test-phase1.sh
```

Run the relevant [integration fixtures](TEST_PLAN.md) and record any checks
blocked by kernel support or privileges. The BPF loader and namespace
fixtures may need sudo. Run the IDE, builds, and offline analysis as a
normal user. Ordinary userspace debuggers can inspect the Rust executable.
Use verifier diagnostics and the fixtures to inspect BPF behavior.

For patch scope and acceptance requirements, see the
[project contract](../AGENTS.md). The original incremental development
prompts are kept in [prompts/CODEX_TASKS.md](../prompts/CODEX_TASKS.md).
