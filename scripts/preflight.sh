#!/usr/bin/env bash
set -u
printf '=== identity ===\n'
hostname; uname -a; uname -m; id
printf '\n=== distribution ===\n'
cat /etc/os-release 2>/dev/null || true
printf '\n=== memory / disk ===\n'
free -h 2>/dev/null || true
df -h "$HOME" 2>/dev/null || true
printf '\n=== toolchain ===\n'
for t in rustc cargo clang llc llvm-objdump bpftool pkg-config git ip tc tcpdump; do
  printf '%-17s' "$t"
  if command -v "$t" >/dev/null 2>&1; then command -v "$t"; else echo MISSING; fi
done
printf '\n=== BTF ===\n'
ls -lh /sys/kernel/btf/vmlinux 2>&1 || true
printf '\n=== tracefs ===\n'
for p in /sys/kernel/tracing/events/tcp /sys/kernel/tracing/events/skb /sys/kernel/debug/tracing/events/tcp /sys/kernel/debug/tracing/events/skb; do
  if test -d "$p"; then printf '%s: available\n' "$p"; else printf '%s: unavailable\n' "$p"; fi
done
printf '\n=== kernel configuration (if exposed) ===\n'
for f in "/boot/config-$(uname -r)" /proc/config.gz; do
  if test -r "$f"; then echo "$f present"; fi
done
printf '\nNOTE: No sudo, packages, network settings, or kernel settings changed.\n'
