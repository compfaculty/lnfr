#!/usr/bin/env python3
"""Measure TCP churn with no observer, the collector, and the live terminal UI."""

import argparse
from contextlib import ExitStack
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import termios
import threading
import time

SERVER = """
from pathlib import Path
import socket, sys
with socket.socket() as listener:
    listener.bind(("192.0.2.2", 0))
    listener.listen(128)
    Path(sys.argv[1]).write_text(str(listener.getsockname()[1]))
    while True:
        peer, _ = listener.accept()
        with peer:
            try:
                if peer.recv(1):
                    peer.sendall(b"R")
            except OSError:
                pass
"""

CLIENT = """
import json, math, socket, sys, time
port, rate, seconds = map(int, sys.argv[1:])
latencies = []
errors = 0
start = time.monotonic()
for index in range(rate * seconds):
    delay = start + index / rate - time.monotonic()
    if delay > 0:
        time.sleep(delay)
    if time.monotonic() >= start + seconds:
        break
    before = time.perf_counter_ns()
    try:
        with socket.socket() as client:
            client.settimeout(1)
            client.connect(("192.0.2.2", port))
            client.sendall(b"B")
            assert client.recv(1) == b"R"
    except (AssertionError, OSError):
        errors += 1
    else:
        latencies.append((time.perf_counter_ns() - before) / 1_000)
remaining = start + seconds - time.monotonic()
if remaining > 0:
    time.sleep(remaining)
elapsed = time.monotonic() - start
latencies.sort()
def percentile(value):
    return latencies[max(0, math.ceil(value * len(latencies)) - 1)] if latencies else None
print(json.dumps({"elapsed_s": elapsed, "offered": rate * seconds, "completed": len(latencies),
                  "errors": errors, "not_started": rate * seconds - len(latencies) - errors,
                  "connections_per_s": len(latencies) / elapsed, "p50_us": percentile(.50),
                  "p95_us": percentile(.95), "p99_us": percentile(.99)}))
"""


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, timeout=10)


def reap(process, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return {"cpu_s": usage.ru_utime + usage.ru_stime, "max_rss_kib": usage.ru_maxrss}
        time.sleep(.02)
    raise TimeoutError(f"process {process.pid} did not stop")


def stop(process):
    if process.returncode is None:
        process.terminate()
        if process.returncode is not None:
            return
        try:
            reap(process, 2)
        except TimeoutError:
            process.kill()
            reap(process, 3)


def child(stack, *args, **kwargs):
    process = subprocess.Popen(args, **kwargs)
    stack.callback(stop, process)
    return process


def wait_for(predicate, description, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.025)
    raise TimeoutError(description)


class Terminal:
    def __init__(self, stack):
        self.master, self.slave = pty.openpty()
        stack.callback(os.close, self.master)
        stack.callback(os.close, self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 126, 0, 0))
        self.tail = bytearray()
        self.reading = threading.Event()
        self.reading.set()
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        stack.callback(self.close)

    def read(self):
        while self.reading.is_set():
            if not select.select([self.master], [], [], .05)[0]:
                continue
            try:
                block = os.read(self.master, 64 * 1024)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            self.tail.extend(block)
            del self.tail[:-131_072]

    def close(self):
        self.reading.clear()
        self.thread.join(timeout=2)

    def summary(self):
        # The summary is printed after Ratatui exits the alternate screen.
        # A raw redraw can contain braces on the same physical output line.
        _, restored, output = bytes(self.tail).rpartition(b"\x1b[?1049l")
        if not restored:
            return None
        decoder = json.JSONDecoder()
        for candidate in output.splitlines():
            start = candidate.find(b"{")
            if start < 0:
                continue
            try:
                row, _ = decoder.raw_decode(candidate[start:].decode())
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(row, dict) and row.get("record") == "capture_end":
                return row
        return None


def task_metrics(pid):
    path = Path(f"/proc/{pid}")
    stat = (path / "stat").read_text().rsplit(") ", 1)[1].split()
    hwm = re.search(r"^VmHWM:\s+(\d+)", (path / "status").read_text(), re.M)
    return (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"), int(hwm[1])


def capture_summary(path):
    # Events are written to temporary files on all capture-only runs.
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 16_384))
        for line in reversed(stream.readlines()):
            if b'"record":"capture_end"' in line:
                return json.loads(line)
    return None


def benchmark(binary, client, server, inode, root, rate, duration, mode, repeat):
    with ExitStack() as stack:
        stem = root / f"{rate}-{mode}-{repeat}"
        port_file = stem.with_suffix(".port")
        peer = child(stack, "ip", "netns", "exec", server, sys.executable, "-c", SERVER,
                     str(port_file))
        port = wait_for(lambda: port_file.read_text() if port_file.exists() else None,
                        "server did not publish its port")
        observer = screen = None
        capture_file = stem.with_suffix(".capture")
        errors = stack.enter_context(stem.with_suffix(".stderr").open("w"))
        if mode == "capture":
            out = stack.enter_context(capture_file.open("w"))
            observer = child(stack, binary, "capture", "--stop-on-stdin-eof", "--netns-inum",
                             str(inode), stdin=subprocess.PIPE, stdout=out, stderr=errors)
            try:
                wait_for(lambda: capture_file.stat().st_size > 0, "collector did not attach")
            except TimeoutError as error:
                raise RuntimeError(f"{error}: {stem.with_suffix('.stderr').read_text()}") from error
        elif mode == "tui":
            screen = Terminal(stack)
            observer = child(stack, binary, "tui", "--live", "--summary", "--netns-inum",
                             str(inode), stdin=screen.slave, stdout=screen.slave, stderr=errors,
                             env={**os.environ, "TERM": "xterm-256color"})
            try:
                wait_for(lambda: b"Live TCP" in screen.tail, "live TUI did not start its collector")
            except TimeoutError as error:
                raise RuntimeError(f"{error}: {stem.with_suffix('.stderr').read_text()}") from error

        output_file = stem.with_suffix(".workload")
        with output_file.open("w") as output:
            workload = child(stack, "ip", "netns", "exec", client, sys.executable, "-c", CLIENT,
                             port, str(rate), str(duration), stdout=output)
            client_usage = reap(workload, duration + 5)
        if workload.returncode != 0:
            raise RuntimeError(f"workload exited {workload.returncode}")
        result = json.loads(output_file.read_text())
        peer.terminate()
        if peer.returncode is not None:
            raise RuntimeError(f"benchmark server exited early: {peer.returncode}")
        server_usage = reap(peer)
        result.update(mode=mode, rate=rate, repeat=repeat, client=client_usage, server=server_usage)
        if observer:
            result["observer_main_cpu_s_before_stop"], result["observer_main_hwm_kib"] = task_metrics(observer.pid)
            if screen:
                descendants = Path(f"/proc/{observer.pid}/task/{observer.pid}/children").read_text().split()
                if len(descendants) == 1:
                    result["tui_collector_cpu_s_before_stop"], result["tui_collector_hwm_kib"] = task_metrics(int(descendants[0]))
                os.write(screen.master, b"q")
            else:
                observer.stdin.close()
            result["observer"] = reap(observer)
            if observer.returncode != 0:
                raise RuntimeError(stem.with_suffix(".stderr").read_text())
            summary = (wait_for(screen.summary, "live TUI summary missing after terminal restore") if screen
                       else capture_summary(capture_file))
            if not summary:
                raise RuntimeError(f"{mode} emitted no final capture summary")
            result["capture"] = {key: summary[key] for key in ("elapsed_ms", "received", "stats")}
            if summary["received"] != summary["stats"]["submitted"]:
                raise RuntimeError(f"capture count mismatch: {summary}")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/lnfr")
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--rates", type=int, nargs="+", default=[20, 600])
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.duration <= 30 or not 1 <= args.repeats <= 5 or not all(1 <= rate <= 2000 for rate in args.rates):
        parser.error("duration 1–30s, repeats 1–5, and rates 1–2000 connections/s")
    if os.geteuid() != 0:
        parser.error("run the isolated benchmark with sudo on the Kali test host")
    binary = str(Path(args.binary).resolve(strict=True))
    client, server = f"lnfr6-c-{os.getpid()}", f"lnfr6-s-{os.getpid()}"
    with ExitStack() as stack:
        root = Path(stack.enter_context(TemporaryDirectory(prefix="lnfr-bench-")))
        for ns in (client, server):
            run("ip", "netns", "add", ns)
            stack.callback(run, "ip", "netns", "del", ns)
        run("ip", "-n", client, "link", "add", "lnfr0", "type", "veth",
            "peer", "name", "lnfr0", "netns", server)
        for ns, address in ((client, "192.0.2.1"), (server, "192.0.2.2")):
            run("ip", "-n", ns, "addr", "add", address + "/30", "dev", "lnfr0")
            run("ip", "-n", ns, "link", "set", "lnfr0", "up")
        inode = os.stat(f"/run/netns/{client}").st_ino
        print(json.dumps({"kernel": os.uname().release, "host": os.uname().nodename,
                          "duration_s": args.duration, "repeats": args.repeats,
                          "terminal": "126x36 local PTY"}), flush=True)
        for repeat in range(1, args.repeats + 1):
            for rate in args.rates:
                modes = ("baseline", "capture", "tui") if repeat % 2 else ("tui", "capture", "baseline")
                for mode in modes:
                    print(json.dumps(benchmark(binary, client, server, inode, root, rate,
                                               args.duration, mode, repeat)), flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main()
