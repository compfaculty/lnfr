#!/usr/bin/env bash
# Verify IPv4 and IPv6 routing between two veth subnets.
set -euo pipefail

if (( EUID != 0 )); then
    echo "Run this fixture with sudo on the Kali test host." >&2
    exit 2
fi

nfr=$(realpath "${1:-target/debug/nfr}")
test -x "$nfr" || { echo "Build nfr first: cargo build --locked" >&2; exit 2; }
tmp=$(mktemp -d)
client="nfr4-route-client-$$"
router="nfr4-route-router-$$"
server="nfr4-route-server-$$"
namespaces=()
children=()

cleanup() {
    for pid in "${children[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || true; done
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

for namespace in "$client" "$router" "$server"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
done

ip -n "$router" link add left type veth peer name nfr0 netns "$client"
ip -n "$router" link add right type veth peer name nfr0 netns "$server"

address_link() {
    local ns=$1 dev=$2 ipv4=$3 ipv6=$4
    ip -n "$ns" addr add "$ipv4/30" dev "$dev"
    ip -n "$ns" -6 addr add "$ipv6/64" dev "$dev" nodad
    ip -n "$ns" link set "$dev" up
}

address_link "$client" nfr0 192.0.2.2 2001:db8:10::2
address_link "$router" left 192.0.2.1 2001:db8:10::1
address_link "$router" right 198.51.100.1 2001:db8:20::1
address_link "$server" nfr0 198.51.100.2 2001:db8:20::2
ip -n "$client" -4 route add 198.51.100.0/30 via 192.0.2.1
ip -n "$server" -4 route add 192.0.2.0/30 via 198.51.100.1
ip -n "$client" -6 route add 2001:db8:20::/64 via 2001:db8:10::1
ip -n "$server" -6 route add 2001:db8:10::/64 via 2001:db8:20::1

router_net=(nsenter "--net=/run/netns/$router" --)
"${router_net[@]}" sysctl -qw net.ipv4.ip_forward=1
"${router_net[@]}" sysctl -qw net.ipv6.conf.all.forwarding=1
netns=$(stat -Lc %i "/run/netns/$router")
client_netns=$(stat -Lc %i "/run/netns/$client")
ip -n "$router" -j link show >"$tmp/interfaces.json"
ip -n "$router" -j -4 route get 198.51.100.2 from 192.0.2.2 iif left >"$tmp/route4.json"
ip -n "$router" -j -4 route get 192.0.2.2 from 198.51.100.2 iif right >"$tmp/reply4.json"
ip -n "$router" -j -6 route get 2001:db8:20::2 from 2001:db8:10::2 iif left >"$tmp/route6.json"
ip -n "$router" -j -6 route get 2001:db8:10::2 from 2001:db8:20::2 iif right >"$tmp/reply6.json"
bpftool -j prog show >"$tmp/programs-before.json"

ip netns exec "$server" python3 - "$tmp/ports" <<'PY' &
from pathlib import Path
import socket
import sys

with socket.socket(socket.AF_INET) as v4, socket.socket(socket.AF_INET6) as v6:
    for listener, address in ((v4, "198.51.100.2"), (v6, "2001:db8:20::2")):
        listener.bind((address, 0))
        listener.listen()
        listener.settimeout(25)
    temporary = Path(sys.argv[1] + ".new")
    temporary.write_text(f"{v4.getsockname()[1]} {v6.getsockname()[1]}\n")
    temporary.rename(sys.argv[1])
    for listener in (v4, v6):
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            assert conn.recv(1) == b"R"
            conn.sendall(b"A")
PY
server_pid=$!
children+=("$server_pid")
wait_for '^[0-9][0-9]* [0-9][0-9]*$' "$tmp/ports" "$server_pid"
read -r port4 port6 <"$tmp/ports"

env --default-signal=INT "${router_net[@]}" "$nfr" capture --routing --duration 25s \
    --netns-inum "$client_netns" >"$tmp/session.jsonl" &
capture_pid=$!
children+=("$capture_pid")
wait_for '"record":"capture_start"' "$tmp/session.jsonl" "$capture_pid"
bpftool -j prog show >"$tmp/programs-during.json"

sniffers=()
for device in left right; do
    env --default-signal=INT "${router_net[@]}" tcpdump --immediate-mode -p -nn -l \
        -i "$device" tcp >"$tmp/$device.wire" 2>"$tmp/$device.stderr" &
    sniffers+=("$!")
    children+=("$!")
    wait_for 'listening on' "$tmp/$device.stderr" "$!"
done

timeout 12s ip netns exec "$client" python3 - "$port4" "$port6" >"$tmp/source-ports" <<'PY'
import socket
import sys

rows = [
    (socket.AF_INET, socket.IPPROTO_IP, socket.IP_TTL, 48, "198.51.100.2"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 52, "2001:db8:20::2"),
]
source_ports = []
for (family, level, option, hops, address), port in zip(rows, map(int, sys.argv[1:])):
    with socket.socket(family) as sock:
        sock.setsockopt(level, option, hops)
        sock.connect((address, port))
        sock.settimeout(5)
        sock.sendall(b"R")
        assert sock.recv(1) == b"A"
        source_ports.append(sock.getsockname()[1])
print(*source_ports)
PY

wait "$server_pid"
read -r src4 src6 <"$tmp/source-ports"
wait_for '"record":"route_forward"' "$tmp/session.jsonl" "$capture_pid"
for i in 0 1; do
    device=left
    if [[ $i == 1 ]]; then device=right; fi
    wait_for "192\.0\.2\.2\.$src4 > 198\.51\.100\.2\.$port4: Flags \[S\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
    wait_for "198\.51\.100\.2\.$port4 > 192\.0\.2\.2\.$src4: Flags \[S\.\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
    wait_for "2001:db8:10::2\.$src6 > 2001:db8:20::2\.$port6: Flags \[S\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
    wait_for "2001:db8:20::2\.$port6 > 2001:db8:10::2\.$src6: Flags \[S\.\]" \
        "$tmp/$device.wire" "${sniffers[$i]}"
done
kill -INT "$capture_pid" "${sniffers[@]}"
wait "$capture_pid"
for pid in "${sniffers[@]}"; do wait "$pid"; done
children=()

bpftool -j prog show >"$tmp/programs-after.json"
"$nfr" routes --input "$tmp/session.jsonl" >"$tmp/routes.jsonl"
"$nfr" flows --input "$tmp/session.jsonl" >"$tmp/flows.jsonl"

python3 - "$tmp" "$netns" <<'PY'
import json
import sys
from pathlib import Path

root, netns = Path(sys.argv[1]), int(sys.argv[2])
def load(name):
    return json.loads((root / name).read_text())

def jsonl(name):
    return [json.loads(line) for line in (root / name).read_text().splitlines()]

def programs(stage):
    return {p["id"] for p in load(f"programs-{stage}.json")
            if p.get("name") in {"on_ipv4_forward", "on_ipv6_forward"}}

interfaces = {d["ifname"]: d["ifindex"] for d in load("interfaces.json")}
start, *events, end = jsonl("session.jsonl")
assert start["routing_netns_inum"] == netns, start
assert {"fentry/ip_forward", "fentry/ip6_forward"} <= set(start["active_probes"]), start
assert end["reason"] == "signal" and end["received"] == len(events) == end["stats"]["submitted"], end
assert end["stats"]["ring_lost"] == end["stats"]["rate_limited"] == 0, end
assert len(programs("during") - programs("before")) == 2
assert not programs("after") - programs("before")
assert jsonl("flows.jsonl"), "Expected socket events in mixed capture"

routes = jsonl("routes.jsonl")
assert all(row["event"]["netns_inum"] == netns for row in routes), routes
for version, src, dst, hops, hook in (
    (4, "192.0.2.2", "198.51.100.2", 48, "fentry/ip_forward"),
    (6, "2001:db8:10::2", "2001:db8:20::2", 52, "fentry/ip6_forward"),
):
    for lane, source, destination, ingress, hop_limit in (
        ("route", src, dst, "left", hops), ("reply", dst, src, "right", None),
    ):
        selected = load(f"{lane}{version}.json")[0]["dev"]
        assert selected == ("right" if ingress == "left" else "left"), selected
        observation = next(row for row in routes if row["event"]["hook"] == hook
                           and row["event"]["src"] == source and row["event"]["dst"] == destination
                           and row["event"]["ip_next_header"] == 6)
        event = observation["event"]
        assert event["ip_version"] == version and event["ingress_ifindex"] == interfaces[ingress], event
        assert event["egress_ifindex"] == interfaces[selected] and event["skb_len"] > 0, event
        if hop_limit is not None:
            assert event["hop_limit"] == hop_limit, event
            print(json.dumps(observation, separators=(",", ":")))
print("PASS: IPv4 and IPv6 forwarding match ip route get, tcpdump, and clean detach")
PY
