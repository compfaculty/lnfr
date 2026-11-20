#!/usr/bin/env python3
"""Privileged Kali integration fixture, restricted to disposable veth namespaces."""

import argparse
import errno
import json
import os
from contextlib import ExitStack
from pathlib import Path
import re
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT6 = "2001:db8:2::1"
SERVER6 = "2001:db8:2::2"
HOOKS = {
    "sock:inet_sock_set_state",
    "tcp:tcp_retransmit_skb",
    "fentry/inet_stream_connect",
    "fexit/inet_stream_connect",
    "fexit/inet_csk_accept",
}

SERVER_CODE = """
import json
from pathlib import Path
import socket
import sys

with (socket.socket() as normal, socket.socket() as lossy,
      socket.socket() as closed, socket.socket() as timeout,
      socket.socket(socket.AF_INET6) as ipv6):
    for sock in (normal, lossy, closed, timeout):
        sock.bind(("192.0.2.2", 0))
    ipv6.bind(("2001:db8:2::2", 0))
    for sock in (normal, lossy, timeout, ipv6):
        sock.settimeout(35)
        sock.listen()
    Path(sys.argv[1]).write_text(json.dumps({
        name: sock.getsockname()[1] for name, sock in
        zip(("normal", "lossy", "closed", "timeout", "ipv6"), (normal, lossy, closed, timeout, ipv6))
    }))
    for listener in (normal, lossy, ipv6):
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(25)
            connection.recv(1)
"""

CLIENT_CODE = """
import errno
import json
import socket
import sys

local, remote, port, mode = sys.argv[1:]
family = socket.AF_INET6 if ":" in local else socket.AF_INET
with socket.socket(family) as sock:
    sock.bind((local, 0))
    print(json.dumps({"local_port": sock.getsockname()[1]}), flush=True)
    expected_errors = {"closed": errno.ECONNREFUSED, "timeout": errno.ETIMEDOUT}
    if mode == "timeout":
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 1)
    try:
        sock.connect((remote, int(port)))
    except OSError as error:
        if error.errno != expected_errors.get(mode):
            raise
        print(json.dumps({"errno": error.errno}), flush=True)
    else:
        if mode in expected_errors:
            raise SystemExit(f"The {mode} scenario unexpectedly connected")
        print(json.dumps({"connected": True}), flush=True)
        if mode == "normal":
            sys.stdin.readline()
"""


def run(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def child(stack, args, **kwargs):
    process = subprocess.Popen(args, **kwargs)
    stack.callback(process.wait)
    stack.callback(stop, process)
    return process


def wait_for(predicate, label, *processes, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        for process in processes:
            status = process.poll()
            if status is not None and status != 0:
                raise RuntimeError(f"{label}: process {process.pid} exited with {status}")
        time.sleep(0.03)
    raise RuntimeError(f"Timed out waiting for {label}")


def records(path):
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    return [json.loads(line) for line in lines if line.endswith("\n")]


def read_values(path, count, process, seconds=8):
    return wait_for(
        lambda: (values if len(values := records(path)) >= count else None),
        str(path.name),
        process,
        seconds=seconds,
    )


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def match(events, record, local, remote, local_port=None, remote_port=None):
    def endpoint(actual, address, port):
        return actual["address"] == address and (port is None or actual["port"] == port)

    return next(
        (
            event for event in events
            if event["record"] == record
            and endpoint(event["local"], local, local_port)
            and endpoint(event["remote"], remote, remote_port)
        ),
        None,
    )


def summary(items, namespace):
    header, *events, end = items
    require(header["record"] == "capture_start", header)
    require(set(header["active_probes"]) == HOOKS, header["disabled_probes"])
    require(header["netns_inum_filter"] == namespace, header)
    require(end["record"] == "capture_end" and end["reason"] == "signal", end)
    require(end["received"] == len(events) == end["stats"]["submitted"], end)
    require(all(end["stats"][key] == 0 for key in (
        "ring_lost", "rate_limited", "connect_tracking_lost"
    )), end)
    require(all(event["schema_version"] == 2 and event["netns_inum"] == namespace
                for event in events), events)
    return events, end


def verify_diagnoses(binary, path, expected):
    flows = [json.loads(line) for line in run(binary, "flows", "--input", str(path)).splitlines()]
    found = set()
    for flow in flows:
        report = json.loads(run(binary, "explain", "--input", str(path), "--flow", flow["flow_id"]))
        evidence = {item["evidence_id"]: item["event"] for item in report["timeline"]}
        times = [event["monotonic_ns"] for event in evidence.values()]
        require(times == sorted(times), report)
        require(any("Packet loss location" in limit for limit in report["blind_spots"]), report)
        for diagnosis in report["diagnoses"]:
            code = diagnosis["code"]
            ids = diagnosis["evidence_ids"]
            require(ids and all(identifier in evidence for identifier in ids), diagnosis)
            if code in {"completion_not_observed", "insufficient_evidence"}:
                require(diagnosis["confidence"] == "unknown", diagnosis)
            if code in expected:
                event = expected[code]
                if event in (evidence[identifier] for identifier in ids):
                    require(diagnosis["confidence"] == "confirmed", diagnosis)
                    if code == "retransmit_observed":
                        require(any("cause are unproven" in item
                                    for item in diagnosis["alternatives"]), diagnosis)
                    found.add(code)
    require(found == set(expected), f"Missing evidence-backed diagnoses: {set(expected) - found}")


def main(binary, emit_client_jsonl=False):
    suffix = str(os.getpid())
    client_ns = f"lnfr2-client-{suffix}"
    server_ns = f"lnfr2-server-{suffix}"
    with ExitStack() as stack:
        temp = Path(stack.enter_context(TemporaryDirectory(prefix="lnfr-phase2-")))
        for namespace in (client_ns, server_ns):
            run("ip", "netns", "add", namespace)
            stack.callback(run, "ip", "netns", "del", namespace)

        run("ip", "-n", client_ns, "link", "add", "lnfr0", "type", "veth",
            "peer", "name", "lnfr0", "netns", server_ns)
        for namespace, addr, addr6 in (
            (client_ns, CLIENT, CLIENT6), (server_ns, SERVER, SERVER6)
        ):
            run("ip", "-n", namespace, "addr", "add", f"{addr}/30", "dev", "lnfr0")
            run("ip", "-n", namespace, "-6", "addr", "add", f"{addr6}/64", "dev", "lnfr0", "nodad")
            run("ip", "-n", namespace, "link", "set", "lnfr0", "up")

        def capture(namespace):
            inode = os.stat(f"/run/netns/{namespace}").st_ino
            path = temp / f"{namespace}.jsonl"
            with path.open("w") as output:
                process = child(stack, (binary, "capture", "--duration", "45s", "--netns-inum",
                                        str(inode)), stdout=output)
            header = read_values(path, 1, process)[0]
            require(set(header["active_probes"]) == HOOKS, header["disabled_probes"])
            return path, process, inode

        client_path, client_capture, client_inode = capture(client_ns)
        server_path, server_capture, server_inode = capture(server_ns)

        ports_path = temp / "ports.json"
        server = child(stack, ("ip", "netns", "exec", server_ns, sys.executable,
                               "-c", SERVER_CODE, str(ports_path)))
        wait_for(lambda: ports_path.exists() and ports_path.stat().st_size, "listening sockets", server)
        ports = json.loads(ports_path.read_text())

        wire_path, ready_path = temp / "wire.log", temp / "tcpdump.log"
        with wire_path.open("w") as output, ready_path.open("w") as diagnostic:
            wire = child(stack, ("ip", "netns", "exec", client_ns, "tcpdump", "--immediate-mode", "-nn", "-p", "-l",
                                 "-i", "lnfr0", "tcp"), stdout=output, stderr=diagnostic)
        wait_for(lambda: "listening on" in ready_path.read_text(), "tcpdump readiness", wire)

        def client(mode, local=CLIENT, remote=SERVER):
            path = temp / f"{mode}.jsonl"
            with path.open("w") as output:
                process = child(stack, ("ip", "netns", "exec", client_ns, sys.executable, "-c",
                                        CLIENT_CODE, local, remote, str(ports[mode]), mode),
                                stdout=output, stdin=subprocess.PIPE, text=True)
            return path, process

        normal_path, normal = client("normal")
        normal_result = read_values(normal_path, 2, normal)
        normal_port = normal_result[0]["local_port"]
        require(normal_result[1]["connected"], normal_result)
        sockets = run("ip", "netns", "exec", client_ns, "ss", "-tnH", "state", "established")
        require(f"{CLIENT}:{normal_port}" in sockets and f"{SERVER}:{ports['normal']}" in sockets,
                f"N1: established socket missing from ss: {sockets}")
        normal.stdin.close()
        require(normal.wait(timeout=5) == 0, "N1 client failed")

        closed_path, closed = client("closed")
        closed_result = read_values(closed_path, 2, closed)
        require(closed_result[1]["errno"] == errno.ECONNREFUSED, closed_result)
        require(closed.wait(timeout=5) == 0, "N2 client failed")

        tc = ("ip", "netns", "exec", server_ns, "tc")
        run(*tc, "qdisc", "add", "dev", "lnfr0", "root", "netem", "loss", "100%")
        lossy_path, lossy = client("lossy")
        lossy_port = read_values(lossy_path, 1, lossy)[0]["local_port"]
        retransmit = wait_for(
            lambda: match(records(client_path), "tcp_retransmit", CLIENT, SERVER,
                          lossy_port, ports["lossy"]),
            "N3 client TCP retransmission",
            client_capture, lossy,
        )
        qdisc = run(*tc, "-s", "qdisc", "show", "dev", "lnfr0")
        require(re.search(r"dropped [1-9][0-9]*", qdisc), f"N3: netem reported no drops: {qdisc}")
        run(*tc, "qdisc", "del", "dev", "lnfr0", "root")
        require(read_values(lossy_path, 2, lossy)[1]["connected"], "N3 did not recover")
        require(lossy.wait(timeout=5) == 0, "N3 client failed")

        run(*tc, "qdisc", "add", "dev", "lnfr0", "root", "netem", "loss", "100%")
        timeout_path, timed = client("timeout")
        timed_result = read_values(timeout_path, 2, timed, seconds=18)
        require(timed_result[1]["errno"] == errno.ETIMEDOUT, timed_result)
        require(timed.wait(timeout=5) == 0, "N4 client failed")
        run(*tc, "qdisc", "del", "dev", "lnfr0", "root")

        ipv6_path, ipv6 = client("ipv6", CLIENT6, SERVER6)
        ipv6_result = read_values(ipv6_path, 2, ipv6)
        require(ipv6_result[1]["connected"], ipv6_result)
        require(ipv6.wait(timeout=5) == server.wait(timeout=5) == 0, "N8 connection failed")

        for process in (client_capture, server_capture, wire):
            process.send_signal(signal.SIGINT)
            require(process.wait(timeout=5) == 0, f"Process {process.pid} failed on SIGINT")

        client_events, client_end = summary(records(client_path), client_inode)
        server_events, server_end = summary(records(server_path), server_inode)
        connected = match(client_events, "tcp_connect", CLIENT, SERVER, normal_port, ports["normal"])
        accepted = match(server_events, "tcp_accept", SERVER, CLIENT, ports["normal"], normal_port)
        require(connected and connected["result"] == 0 and connected["connect_elapsed_ns"] is not None,
                f"N1: missing successful connect with timing: {connected}")
        require(accepted, "N1: missing matching TCP accept")
        transitions = [event for event in client_events if event["record"] == "socket_state"
                       and event["local"]["port"] == normal_port
                       and event["remote"]["port"] == ports["normal"]]
        require(any((event["oldstate"], event["newstate"]) == (7, 2) for event in transitions)
                and any(event["newstate"] == 1 for event in transitions),
                f"N1: missing CLOSE → SYN_SENT or ESTABLISHED: {transitions}")

        refused = next((event for event in client_events if event["record"] == "tcp_connect"
                        and event["requested_peer"] == {"address": SERVER, "port": ports["closed"]}), None)
        require(refused and refused["result"] == -errno.ECONNREFUSED, f"N2: missing refusal: {refused}")
        wire_lines = wire_path.read_text().splitlines()
        require(any(f"{SERVER}.{ports['closed']} > {CLIENT}.{closed_result[0]['local_port']}" in line
                    and "Flags [R" in line for line in wire_lines), "N2: tcpdump did not see the RST")
        require(sum(f"{CLIENT}.{lossy_port} > {SERVER}.{ports['lossy']}" in line
                    and "Flags [S]" in line for line in wire_lines) >= 2,
                "N3: tcpdump did not see repeated SYNs")

        ipv6_port = ipv6_result[0]["local_port"]
        connected6 = match(client_events, "tcp_connect", CLIENT6, SERVER6, ipv6_port, ports["ipv6"])
        accepted6 = match(server_events, "tcp_accept", SERVER6, CLIENT6, ports["ipv6"], ipv6_port)
        require(connected6 and connected6["result"] == 0 and accepted6,
                f"N8: missing IPv6 connect or accept: {connected6}, {accepted6}")
        timeout = next((event for event in client_events if event["record"] == "tcp_connect"
                        and event["requested_peer"] == {"address": SERVER, "port": ports["timeout"]}), None)
        require(timeout and timeout["result"] == -errno.ETIMEDOUT, f"N4: missing timeout: {timeout}")
        verify_diagnoses(binary, client_path, {
            "connection_established": connected,
            "connection_refused": refused,
            "retransmit_observed": retransmit,
            "connect_timeout": timeout,
        })
        verify_diagnoses(binary, server_path, {"connection_established": accepted})
        if emit_client_jsonl:
            sys.stdout.write(client_path.read_text())
            print("PASS: verified veth fixture; exported the client capture", file=sys.stderr)
            return
        for event in (connected, accepted, refused, retransmit, timeout, connected6, client_end, server_end):
            print(json.dumps(event, separators=(",", ":")))
        print("PASS: N1 TCP lifecycle, N2 refusal, N3 retransmission, N4 timeout, N8 IPv6, and Phase 3 evidence")


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run this fixture with sudo on the Kali test host.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lnfr_binary", nargs="?", default="target/debug/lnfr")
    parser.add_argument("--emit-client-jsonl", action="store_true",
                        help="write the verified client capture to stdout")
    options = parser.parse_args()
    binary = Path(options.lnfr_binary).resolve()
    if not os.access(binary, os.X_OK):
        raise SystemExit("Build lnfr first: cargo build --locked")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main(str(binary), options.emit_client_jsonl)
