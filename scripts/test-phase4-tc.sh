#!/usr/bin/env bash
# Host-specific passive TCX integration fixture.
set -euo pipefail

if (( EUID != 0 )); then
    echo "Run this fixture with sudo on the Kali test host." >&2
    exit 2
fi

nfr=$(realpath "${1:-target/debug/nfr}")
test -x "$nfr" || { echo "Build nfr first: cargo build --locked" >&2; exit 2; }
tmp=$(mktemp -d)
client="nfr4-tc-client-$$"
server="nfr4-tc-server-$$"
client_created=0
server_created=0
capture_pid=
tcpdump_pid=
server_pid=

cleanup() {
    for pid in "$capture_pid" "$tcpdump_pid" "$server_pid"; do
        if [[ -n $pid ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if (( client_created )); then ip netns del "$client" || true; fi
    if (( server_created )); then ip netns del "$server" || true; fi
    rm -rf -- "$tmp"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for() {
    local pattern=$1 path=$2 pid=$3
    for ((attempt = 0; attempt < 160; attempt++)); do
        if [[ -f $path ]] && grep -q -- "$pattern" "$path"; then return 0; fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    echo "Timed out waiting for $pattern in $path" >&2
    return 1
}

ip netns add "$client"
client_created=1
ip netns add "$server"
server_created=1
ip -n "$client" link add nfr0 type veth peer name nfr0 netns "$server"
ip -n "$client" addr add 192.0.2.1/30 dev nfr0
ip -n "$server" addr add 192.0.2.2/30 dev nfr0
ip -n "$client" link set nfr0 up
ip -n "$server" link set nfr0 up

netns=$(stat -Lc %i "/run/netns/$client")
client_net=(nsenter "--net=/run/netns/$client" --)
"${client_net[@]}" tc -j qdisc show dev nfr0 >"$tmp/qdisc-before"
"${client_net[@]}" bpftool -j net show dev nfr0 >"$tmp/links-before"
ifindex=$("${client_net[@]}" ip -j link show dev nfr0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["ifindex"])')

ip netns exec "$server" python3 - "$tmp/port" <<'PY' &
import socket
import sys
from pathlib import Path

with socket.socket() as listener:
    listener.bind(("192.0.2.2", 0))
    listener.listen()
    listener.settimeout(20)
    Path(sys.argv[1]).write_text(f"{listener.getsockname()[1]}\n")
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(5)
        assert conn.recv(1) == b"N"
        conn.sendall(b"R")
PY
server_pid=$!
wait_for '^[0-9][0-9]*$' "$tmp/port" "$server_pid"
port=$(cat "$tmp/port")

env --default-signal=INT "${client_net[@]}" "$nfr" capture --duration 20s \
    --tc-interface nfr0 --netns-inum "$netns" >"$tmp/session.jsonl" &
capture_pid=$!
wait_for '"record":"capture_start"' "$tmp/session.jsonl" "$capture_pid"

"${client_net[@]}" tc -j qdisc show dev nfr0 >"$tmp/qdisc-during"

env --default-signal=INT ip netns exec "$client" tcpdump --immediate-mode -p -nn -l -i nfr0 tcp \
    >"$tmp/wire" 2>"$tmp/tcpdump.stderr" &
tcpdump_pid=$!
wait_for 'listening on' "$tmp/tcpdump.stderr" "$tcpdump_pid"

timeout 8s ip netns exec "$client" python3 - "$port" >"$tmp/source-port" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.connect(("192.0.2.2", int(sys.argv[1])))
    sock.settimeout(5)
    sock.sendall(b"N")
    assert sock.recv(1) == b"R"
    print(sock.getsockname()[1])
PY
wait "$server_pid"
server_pid=
wait_for '"record":"tc_packet"' "$tmp/session.jsonl" "$capture_pid"
source_port=$(cat "$tmp/source-port")
if ! wait_for "192\.0\.2\.1\.${source_port} > 192\.0\.2\.2\.${port}: Flags \[S\]" "$tmp/wire" "$tcpdump_pid" ||
   ! wait_for "192\.0\.2\.2\.${port} > 192\.0\.2\.1\.${source_port}: Flags \[S\.\]" "$tmp/wire" "$tcpdump_pid"; then
    cat "$tmp/tcpdump.stderr" "$tmp/wire" >&2
    exit 1
fi
kill -INT "$capture_pid" "$tcpdump_pid"
wait "$capture_pid"
capture_pid=
wait "$tcpdump_pid"
tcpdump_pid=

"${client_net[@]}" tc -j qdisc show dev nfr0 >"$tmp/qdisc-after"
"${client_net[@]}" bpftool -j net show dev nfr0 >"$tmp/links-after"
"$nfr" tc --input "$tmp/session.jsonl" >"$tmp/observations.jsonl"
"$nfr" flows --input "$tmp/session.jsonl" >"$tmp/flows.jsonl"

python3 - "$tmp" "$nfr" "$netns" "$ifindex" "$port" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root, nfr, netns, ifindex, port = sys.argv[1:]
root = Path(root)
netns, ifindex, port = map(int, (netns, ifindex, port))
source_port = int((root / "source-port").read_text())
local = {"address": "192.0.2.1", "port": source_port}
remote = {"address": "192.0.2.2", "port": port}

def jsonl(path):
    return [json.loads(line) for line in (root / path).read_text().splitlines()]

start, *events, end = jsonl("session.jsonl")
assert start["tc_interface"] == {"name": "nfr0", "netns_inum": netns, "ifindex": ifindex}, start
assert {"tcx/ingress", "tcx/egress"} <= set(start["active_probes"]), start
assert end["reason"] == "signal" and end["received"] == len(events) == end["stats"]["submitted"], end
assert end["stats"]["ring_lost"] == end["stats"]["rate_limited"] == 0, end

records = jsonl("observations.jsonl")
assert all(item["event"]["ifindex"] == ifindex and item["event"]["netns_inum"] == netns
           and item["event"]["skb_len"] > 0 for item in records), records
syn = next(item for item in records if item["event"]["direction"] == "egress"
           and item["event"]["src"] == local and item["event"]["dst"] == remote
           and item["event"]["tcp_flags"] & 0x12 == 0x02)
synack = next(item for item in records if item["event"]["direction"] == "ingress"
              and item["event"]["src"] == remote and item["event"]["dst"] == local
              and item["event"]["tcp_flags"] & 0x12 == 0x12)

wire = (root / "wire").read_text().splitlines()
assert any(f"192.0.2.1.{source_port} > 192.0.2.2.{port}" in line and "Flags [S]" in line for line in wire), wire
assert any(f"192.0.2.2.{port} > 192.0.2.1.{source_port}" in line and "Flags [S.]" in line for line in wire), wire

qdiscs = [json.loads((root / f"qdisc-{stage}").read_text()) for stage in ("before", "during", "after")]
assert qdiscs[0] == qdiscs[1] == qdiscs[2], qdiscs
assert json.loads((root / "links-before").read_text()) == json.loads((root / "links-after").read_text())

flow = next(item for item in jsonl("flows.jsonl") if item["tuple"]
            and item["tuple"]["local"] == local and item["tuple"]["remote"] == remote)
report = json.loads(subprocess.check_output(
    [nfr, "explain", "--input", str(root / "session.jsonl"), "--flow", flow["flow_id"]], text=True
))
assert syn in report["tc_observations"] and synack in report["tc_observations"], report
assert not any("counts" in gap for gap in report["capture_gaps"]), report["capture_gaps"]
print(json.dumps(syn, separators=(",", ":")))
print(json.dumps(synack, separators=(",", ":")))
print("PASS: TCX ingress and egress match tcpdump, flow evidence, and clean detach")
PY
