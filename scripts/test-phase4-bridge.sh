#!/usr/bin/env bash
# Observe software forwarding through a disposable bridge namespace.
set -euo pipefail

if (( EUID != 0 )); then
    echo "Run this fixture with sudo on the Kali test host." >&2
    exit 2
fi

nfr=$(realpath "${1:-target/debug/nfr}")
test -x "$nfr" || { echo "Build nfr first: cargo build --locked" >&2; exit 2; }
tmp=$(mktemp -d)
client="nfr4-br-client-$$"
switch="nfr4-br-switch-$$"
server="nfr4-br-server-$$"
client_mac=02:00:00:00:00:11
server_mac=02:00:00:00:00:22
namespaces=()
jobs_to_stop=()

cleanup() {
    for pid in "${jobs_to_stop[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for namespace in "${namespaces[@]}"; do
        ip netns del "$namespace" || true
    done
    rm -rf -- "$tmp"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for() {
    local pattern=$1 file=$2 pid=$3
    for ((attempt = 0; attempt < 160; attempt++)); do
        if [[ -f $file ]] && grep -q -- "$pattern" "$file"; then return 0; fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    echo "Timed out waiting for $pattern in $file" >&2
    if [[ -f $file ]]; then tail -8 "$file" >&2; fi
    return 1
}

for namespace in "$client" "$switch" "$server"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
done

ip -n "$switch" link add br0 type bridge stp_state 0
ip -n "$switch" link add left type veth peer name nfr0 netns "$client"
ip -n "$switch" link add right type veth peer name nfr0 netns "$server"
for port in left right; do
    ip -n "$switch" link set "$port" master br0
    ip -n "$switch" link set "$port" up
done
ip -n "$switch" link set br0 up
ip -n "$client" link set nfr0 address "$client_mac"
ip -n "$server" link set nfr0 address "$server_mac"
ip -n "$client" addr add 192.0.2.1/30 dev nfr0
ip -n "$server" addr add 192.0.2.2/30 dev nfr0
ip -n "$client" link set nfr0 up
ip -n "$server" link set nfr0 up

netns=$(stat -Lc %i "/run/netns/$switch")
client_netns=$(stat -Lc %i "/run/netns/$client")
switch_net=(nsenter "--net=/run/netns/$switch" --)
"${switch_net[@]}" ip -j link show >"$tmp/interfaces.json"
bpftool -j prog show >"$tmp/programs-before.json"

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
        assert conn.recv(1) == b"B"
        conn.sendall(b"R")
PY
server_pid=$!
jobs_to_stop+=("$server_pid")
wait_for '^[0-9][0-9]*$' "$tmp/port" "$server_pid"
port=$(cat "$tmp/port")

env --default-signal=INT "${switch_net[@]}" "$nfr" capture --duration 20s \
    --bridge-interface br0 --netns-inum "$client_netns" >"$tmp/session.jsonl" &
capture_pid=$!
jobs_to_stop+=("$capture_pid")
wait_for '"record":"capture_start"' "$tmp/session.jsonl" "$capture_pid"
bpftool -j prog show >"$tmp/programs-during.json"

sniffers=()
for device in left right; do
    env --default-signal=INT "${switch_net[@]}" tcpdump --immediate-mode -e -p -nn -l \
        -i "$device" tcp >"$tmp/$device.wire" 2>"$tmp/$device.stderr" &
    sniffers+=("$!")
    jobs_to_stop+=("$!")
    wait_for 'listening on' "$tmp/$device.stderr" "$!"
done

timeout 8s ip netns exec "$client" python3 - "$port" >"$tmp/source-port" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.connect(("192.0.2.2", int(sys.argv[1])))
    sock.settimeout(5)
    sock.sendall(b"B")
    assert sock.recv(1) == b"R"
    print(sock.getsockname()[1])
PY
wait "$server_pid"
wait_for '"record":"bridge_forward"' "$tmp/session.jsonl" "$capture_pid"
source_port=$(cat "$tmp/source-port")
for i in 0 1; do
    device=left
    if [[ $i == 1 ]]; then device=right; fi
    wait_for "$client_mac > $server_mac,.*192\.0\.2\.1\.$source_port > 192\.0\.2\.2\.$port: Flags \[S\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
    wait_for "$server_mac > $client_mac,.*192\.0\.2\.2\.$port > 192\.0\.2\.1\.$source_port: Flags \[S\.\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
done

"${switch_net[@]}" bridge fdb show br br0 >"$tmp/fdb"
kill -INT "$capture_pid" "${sniffers[@]}"
wait "$capture_pid"
for pid in "${sniffers[@]}"; do wait "$pid"; done
jobs_to_stop=()

bpftool -j prog show >"$tmp/programs-after.json"
"$nfr" bridge --input "$tmp/session.jsonl" >"$tmp/observations.jsonl"
"$nfr" flows --input "$tmp/session.jsonl" >"$tmp/flows.jsonl"

python3 - "$tmp" "$netns" "$client_mac" "$server_mac" <<'PY'
import json
import sys
from pathlib import Path

root, netns, client, server = sys.argv[1:]
root = Path(root)
netns = int(netns)

def jsonl(path):
    return [json.loads(line) for line in (root / path).read_text().splitlines()]

def program_ids(stage):
    programs = json.loads((root / f"programs-{stage}.json").read_text())
    return {program["id"] for program in programs if program.get("name", "").startswith("on_bridge_")}

interfaces = {item["ifname"]: item["ifindex"]
              for item in json.loads((root / "interfaces.json").read_text())}
start, *events, end = jsonl("session.jsonl")
assert start["bridge_interface"] == {
    "name": "br0", "ifindex": interfaces["br0"], "netns_inum": netns,
}, start
assert "fentry/__br_forward" in start["active_probes"], start
assert end["reason"] == "signal" and end["received"] == len(events) == end["stats"]["submitted"], end
assert end["stats"]["ring_lost"] == end["stats"]["rate_limited"] == 0, end

observations = jsonl("observations.jsonl")

def find(src, dst, ingress, egress):
    return next(item for item in observations if
                item["event"]["src_mac"] == src and item["event"]["dst_mac"] == dst
                and item["event"]["ingress_ifindex"] == interfaces[ingress]
                and item["event"]["egress_ifindex"] == interfaces[egress]
                and item["event"]["bridge_ifindex"] == interfaces["br0"]
                and item["event"]["netns_inum"] == netns
                and item["event"]["ether_type"] == 0x0800 and not item["event"]["local_origin"])

outbound = find(client, server, "left", "right")
inbound = find(server, client, "right", "left")
fdb = (root / "fdb").read_text()
assert any(line.startswith(f"{client} ") and " dev left " in line and " master br0" in line
           for line in fdb.splitlines()), fdb
assert any(line.startswith(f"{server} ") and " dev right " in line and " master br0" in line
           for line in fdb.splitlines()), fdb
assert len(program_ids("during") - program_ids("before")) == 1
assert not program_ids("after") - program_ids("before"), "Bridge BPF program remained loaded"
assert jsonl("flows.jsonl"), "Expected socket events in the mixed capture"
print(json.dumps(outbound, separators=(",", ":")))
print(json.dumps(inbound, separators=(",", ":")))
print("PASS: bridge forwarding matches both veth links, learned FDB entries, and clean detach")
PY
