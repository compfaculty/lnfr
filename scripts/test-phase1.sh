#!/usr/bin/env bash
# Host-specific eBPF integration fixture. Build as the normal user first.
set -euo pipefail

if (( EUID != 0 )); then
    echo "Run this fixture with sudo on the Kali test host." >&2
    exit 2
fi

nfr=${1:-target/debug/nfr}
test -x "$nfr" || { echo "Build nfr first: cargo build --locked" >&2; exit 2; }
tmp=$(mktemp -d)
client_ns="nfr-client-$$"
server_ns="nfr-server-$$"
client_created=0
server_created=0
capture_pid=
client_pid=
server_pid=

cleanup() {
    for pid in "$capture_pid" "$client_pid" "$server_pid"; do
        if [[ -n $pid ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if (( client_created )); then ip netns del "$client_ns"; fi
    if (( server_created )); then ip netns del "$server_ns"; fi
    rm -rf -- "$tmp"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_file() {
    local path=$1 pid=$2
    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -s $path ]] && return 0
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    echo "Fixture timed out waiting for $path (pid $pid)." >&2
    return 1
}

ip netns add "$client_ns"
client_created=1
ip netns add "$server_ns"
server_created=1
ip -n "$client_ns" link add nfr0 type veth peer name nfr0 netns "$server_ns"
ip -n "$client_ns" addr add 192.0.2.1/30 dev nfr0
ip -n "$server_ns" addr add 192.0.2.2/30 dev nfr0
ip -n "$client_ns" link set nfr0 up
ip -n "$server_ns" link set nfr0 up

ip netns exec "$server_ns" python3 - "$tmp/port" <<'PY' &
import socket
import sys
from pathlib import Path

with socket.socket() as listener:
    listener.settimeout(20)
    listener.bind(("192.0.2.2", 0))
    listener.listen()
    Path(sys.argv[1]).write_text(str(listener.getsockname()[1]))
    peer, _ = listener.accept()
    peer.close()
PY
server_pid=$!
wait_for_file "$tmp/port" "$server_pid"

ip netns exec "$client_ns" python3 - "$tmp" <<'PY' &
import os
import socket
import sys
import time
from pathlib import Path

work = Path(sys.argv[1])
(work / "tgid").write_text(str(os.getpid()))
deadline = time.monotonic() + 15
while not (work / "connect").exists():
    if time.monotonic() >= deadline:
        raise SystemExit("Capture never signalled readiness")
    time.sleep(0.02)
port = int((work / "port").read_text())
with socket.create_connection(("192.0.2.2", port), timeout=5):
    pass
PY
client_pid=$!
wait_for_file "$tmp/tgid" "$client_pid"
tgid=$(cat "$tmp/tgid")

# An async Bash child can inherit SIGINT ignored. Reset it before exec so the
# foreground Ctrl+C code path is exercised when the fixture sends SIGINT.
env --default-signal=INT "$nfr" capture --state-only --duration 15s --tgid "$tgid" >"$tmp/capture.jsonl" &
capture_pid=$!
wait_for_file "$tmp/capture.jsonl" "$capture_pid"
touch "$tmp/connect"

wait "$client_pid"
client_pid=
wait "$server_pid"
server_pid=
kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=

"$nfr" capture --state-only --duration 1s --tgid "$tgid" >"$tmp/timed.jsonl"

python3 - "$tmp/capture.jsonl" "$tmp/timed.jsonl" "$tgid" <<'PY'
import json
import sys
from pathlib import Path

capture, timed, tgid = sys.argv[1:]
records = [json.loads(line) for line in Path(capture).read_text().splitlines()]
start, *events, end = records
assert start["record"] == "capture_start", start
assert start["active_probes"] == ["sock:inet_sock_set_state"], start
assert start["context_tgid_filter"] == int(tgid), start
assert end["record"] == "capture_end" and end["reason"] == "signal", end
assert end["received"] == len(events) == end["stats"]["submitted"], end
assert end["stats"]["ring_lost"] == end["stats"]["rate_limited"] == 0, end

expected_transition = None
for event in events:
    assert event["schema_version"] == 2 and event["record"] == "socket_state", event
    assert event["hook"] == "sock:inet_sock_set_state", event
    assert event["context_tgid"] == int(tgid), event
    if (event["family"], event["oldstate"], event["newstate"]) == (2, 7, 2):
        expected_transition = event

assert expected_transition is not None, "Missing the client's IPv4 CLOSE -> SYN_SENT event"

timed_end = json.loads(Path(timed).read_text().splitlines()[-1])
assert timed_end["record"] == "capture_end" and timed_end["reason"] == "duration", timed_end

print(json.dumps(expected_transition, separators=(",", ":")))
print(json.dumps(end, separators=(",", ":")))
print("PASS: veth TCP connect observed through the ring buffer, SIGINT and timeout handled")
PY
