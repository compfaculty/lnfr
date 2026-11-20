#!/usr/bin/env python3
"""Verify conntrack's original and translated tuples in an isolated router."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

CLIENT = "192.0.2.2"
VIP = "203.0.113.9"
ROUTER_OUT = "198.51.100.1"
SERVER = "198.51.100.2"
VIP_PORT = 8443
SNAT_PORT = 40000

SERVER_CODE = """
import json
from pathlib import Path
import socket
import sys

with socket.socket() as server:
    server.bind(("198.51.100.2", 0))
    server.listen()
    server.settimeout(20)
    Path(sys.argv[1]).write_text(str(server.getsockname()[1]))
    conn, peer = server.accept()
    with conn:
        conn.settimeout(5)
        assert conn.recv(1) == b"N"
        conn.sendall(b"R")
        print(json.dumps({"peer": peer, "local": conn.getsockname()}), flush=True)
"""

CLIENT_CODE = """
import json
import socket

with socket.socket() as sock:
    sock.bind(("192.0.2.2", 0))
    sock.connect(("203.0.113.9", 8443))
    sock.settimeout(5)
    sock.sendall(b"N")
    assert sock.recv(1) == b"R"
    print(json.dumps({"local": sock.getsockname(), "peer": sock.getpeername()}), flush=True)
"""


def run(*args, input=None):
    return subprocess.check_output(args, input=input, text=True, timeout=10)


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def child(stack, command, output, diagnostic=None):
    with output.open("w") as stdout:
        process = subprocess.Popen(command, stdout=stdout, stderr=diagnostic)
    stack.callback(stop, process)
    return process


def wait_for(predicate, name, process):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if value := predicate():
            return value
        if process.poll() is not None:
            raise RuntimeError(f"{name}: process exited with status {process.returncode}")
        time.sleep(0.03)
    raise RuntimeError(f"Timed out waiting for {name}")


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines(keepends=True)
            if line.endswith("\n")]


def endpoint(address, port):
    return {"address": address, "port": port}


def main(binary):
    client_ns, router_ns, server_ns = (f"lnfr4-{name}-{os.getpid()}" for name in ("c", "r", "s"))
    with ExitStack() as stack:
        tmp = Path(stack.enter_context(TemporaryDirectory(prefix="lnfr-nat-")))
        for ns in (client_ns, router_ns, server_ns):
            run("ip", "netns", "add", ns)
            stack.callback(run, "ip", "netns", "del", ns)

        run("ip", "-n", router_ns, "link", "add", "left", "type", "veth", "peer", "name",
            "lnfr0", "netns", client_ns)
        run("ip", "-n", router_ns, "link", "add", "right", "type", "veth", "peer", "name",
            "lnfr0", "netns", server_ns)
        for ns, link, address in (
            (client_ns, "lnfr0", CLIENT), (router_ns, "left", "192.0.2.1"),
            (router_ns, "right", ROUTER_OUT), (server_ns, "lnfr0", SERVER)
        ):
            run("ip", "-n", ns, "addr", "add", f"{address}/30", "dev", link)
            run("ip", "-n", ns, "link", "set", link, "up")
        run("ip", "-n", client_ns, "route", "add", f"{VIP}/32", "via", "192.0.2.1")
        router = ("ip", "netns", "exec", router_ns)
        run(*router, "sysctl", "-qw", "net.ipv4.ip_forward=1")

        port_path, server_out = tmp / "port", tmp / "server.json"
        server = child(stack, ("ip", "netns", "exec", server_ns, sys.executable, "-c",
                               SERVER_CODE, str(port_path)), server_out)
        port = wait_for(lambda: int(port_path.read_text() or "0") if port_path.exists() else 0,
                        "server port", server)
        run(*router, "nft", "-f", "-", input=f"""
table ip lnfr_fixture {{
    chain before {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname "left" ip daddr {VIP} tcp dport {VIP_PORT} dnat to {SERVER}:{port}
    }}
    chain after {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "right" ip saddr {CLIENT} ip daddr {SERVER} tcp dport {port} snat to {ROUTER_OUT}:{SNAT_PORT}
    }}
}}
""")
        run(*router, "sysctl", "-qw", "net.netfilter.nf_conntrack_events=1")
        router_inode = os.stat(f"/run/netns/{router_ns}").st_ino
        # Enter only the network namespace. ip netns exec also sets up a
        # mount namespace whose sysfs mount can hide the host's tracefs.
        capture_namespace = ("nsenter", f"--net=/run/netns/{router_ns}", "--")

        captures = []
        for ns, side in ((client_ns, "original"), (server_ns, "translated_reverse")):
            inode = os.stat(f"/run/netns/{ns}").st_ino
            path = tmp / f"{side}.jsonl"
            capture = child(stack, (*capture_namespace, binary, "capture", "--duration", "20s",
                                    "--netns-inum", str(inode), "--conntrack"), path)
            header = wait_for(lambda: next(iter(records(path)), None), "capture header", capture)
            require(header["conntrack_netns_inum"] == router_inode, header)
            require("ctnetlink:conntrack" in header["active_probes"], header)
            captures.append((capture, path, side))

        wires = []
        for link in ("left", "right"):
            wire = tmp / f"{link}.log"
            diag = tmp / f"{link}.stderr"
            with diag.open("w") as output:
                sniffer = child(stack, (*router, "tcpdump", "-p", "-nn", "-l", "-i", link, "tcp"),
                                wire, output)
            wait_for(lambda: "listening on" in diag.read_text(), f"tcpdump on {link}", sniffer)
            wires.append((sniffer, wire))

        client = json.loads(run("ip", "netns", "exec", client_ns, sys.executable, "-c", CLIENT_CODE))
        require(server.wait(timeout=5) == 0, "server failed")
        server_result = json.loads(server_out.read_text())
        require(client["peer"] == [VIP, VIP_PORT], client)
        require(server_result["peer"] == [ROUTER_OUT, SNAT_PORT], server_result)
        require(server_result["local"] == [SERVER, port], server_result)

        original = {"src": endpoint(CLIENT, client["local"][1]), "dst": endpoint(VIP, VIP_PORT)}
        translated = {"src": endpoint(ROUTER_OUT, SNAT_PORT), "dst": endpoint(SERVER, port)}
        reply = {"src": translated["dst"], "dst": translated["src"]}
        capture_evidence = []
        for capture, path, side in captures:
            wait_for(lambda: any(entry["record"] == "conntrack_nat" and entry["notice"] == "new"
                                 for entry in records(path)), "conntrack NEW event", capture)
            capture.send_signal(signal.SIGINT)
            require(capture.wait(timeout=5) == 0, "capture failed on SIGINT")
            end = records(path)[-1]
            stats = end["conntrack_stats"]
            require(end["record"] == "capture_end" and stats["received"] > 0, end)
            require(all(stats[key] == 0 for key in
                        ("overruns", "truncated_datagrams", "decode_errors", "rate_limited")), end)

            events = [json.loads(line) for line in run(binary, "nat", "--input", str(path)).splitlines()]
            match = next((item for item in events if item["event"]["notice"] == "new"
                          and item["event"]["original"] == original), None)
            require(match and match["event"]["reply"] == reply
                    and match["event"]["translated"] == translated
                    and match["event"]["source_nat"] and match["event"]["destination_nat"], events)
            capture_evidence.append(match)

            summaries = [json.loads(line) for line in run(binary, "flows", "--input", str(path)).splitlines()]
            expected = original if side == "original" else reply
            flow = next((flow for flow in summaries if flow["tuple"]
                         and flow["tuple"]["local"] == expected["src"]
                         and flow["tuple"]["remote"] == expected["dst"]), None)
            require(flow, f"No matching socket flow on side {side}")
            report = json.loads(run(binary, "explain", "--input", str(path), "--flow", flow["flow_id"]))
            association = report.get("nat_association")
            require(association and association["side"] == side and association["confidence"] == "possible"
                    and association["translation_confidence"] == "confirmed"
                    and association["evidence"] == match, report)

        for (sniffer, wire), pair in zip(wires, (original, translated)):
            sniffer.send_signal(signal.SIGINT)
            require(sniffer.wait(timeout=5) == 0, "tcpdump failed")
            src, dst = pair["src"], pair["dst"]
            wire_tuple = f"{src['address']}.{src['port']} > {dst['address']}.{dst['port']}"
            require(any(wire_tuple in line and "Flags [S]" in line
                        for line in wire.read_text().splitlines()), wire.read_text())

        print(json.dumps(capture_evidence[0], separators=(",", ":")))
        print("PASS: N5 DNAT and SNAT tuples match both veth links and both socket perspectives")


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run this fixture with sudo on the Kali test host.")
    if len(sys.argv) > 2:
        raise SystemExit(f"Usage: {sys.argv[0]} [lnfr-binary]")
    binary = Path(sys.argv[1] if len(sys.argv) == 2 else "target/debug/lnfr").resolve()
    if not os.access(binary, os.X_OK):
        raise SystemExit("Build lnfr first: cargo build --locked")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main(str(binary))
