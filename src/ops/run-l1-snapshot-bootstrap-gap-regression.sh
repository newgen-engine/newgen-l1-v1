#!/usr/bin/env bash
set -euo pipefail

# NewGen L1 snapshot bootstrap large-gap acceptance check.
#
# This script is intentionally non-destructive: it verifies an already executed
# clean-node bootstrap run by inspecting node status and tmux logs. Use it after
# starting a clean B/D test node against a peer that has bootstrap_latest.
#
# Required/default environment:
#   NEWGEN_CHAIN_ROOT=/srv/newgen/chain
#   NEWGEN_CHAIN_TMUX_SESSION=newgen-chain
#   NEWGEN_SNAPSHOT_PEER_WINDOW=nodeA
#   NEWGEN_SNAPSHOT_TEST_WINDOW=nodeB
#   NEWGEN_SNAPSHOT_TEST_PORT=8002
#   NEWGEN_SNAPSHOT_PEER_SNAPSHOT_DIR=$NEWGEN_CHAIN_ROOT/nodeA/data/snapshots/auto/bootstrap_latest
#   NEWGEN_SNAPSHOT_MIN_PEER_HEIGHT=1000
#   NEWGEN_SNAPSHOT_MAX_REMOTE_APPLIED_LINES=200
#
# PASS criteria:
#   - peer bootstrap_latest meta exists and is above min height;
#   - test node /status responds;
#   - test node height is close to peer snapshot height;
#   - logs show snapshot import/apply path;
#   - logs do not show large_gap_without_snapshot_bootstrap;
#   - RemoteApplied block replay is not dominant.

ROOT="${NEWGEN_CHAIN_ROOT:-/srv/newgen/chain}"
SESSION="${NEWGEN_CHAIN_TMUX_SESSION:-newgen-chain}"
PEER_WINDOW="${NEWGEN_SNAPSHOT_PEER_WINDOW:-nodeA}"
TEST_WINDOW="${NEWGEN_SNAPSHOT_TEST_WINDOW:-nodeB}"
TEST_PORT="${NEWGEN_SNAPSHOT_TEST_PORT:-8002}"
PEER_SNAPSHOT_DIR="${NEWGEN_SNAPSHOT_PEER_SNAPSHOT_DIR:-$ROOT/nodeA/data/snapshots/auto/bootstrap_latest}"
MIN_PEER_HEIGHT="${NEWGEN_SNAPSHOT_MIN_PEER_HEIGHT:-1000}"
MAX_REMOTE_APPLIED_LINES="${NEWGEN_SNAPSHOT_MAX_REMOTE_APPLIED_LINES:-200}"
HEIGHT_LAG_TOLERANCE="${NEWGEN_SNAPSHOT_HEIGHT_LAG_TOLERANCE:-64}"

cd "$ROOT"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

need python3
need curl
need tmux

META="$PEER_SNAPSHOT_DIR/meta.json"
test -f "$META" || fail "peer bootstrap_latest meta not found: $META"

PEER_HEIGHT="$(python3 - "$META" <<'PYJSON'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    print(int(json.load(f).get('height', 0)))
PYJSON
)"

if [ "$PEER_HEIGHT" -lt "$MIN_PEER_HEIGHT" ]; then
  fail "peer snapshot height too low: height=$PEER_HEIGHT min=$MIN_PEER_HEIGHT"
fi

STATUS_FILE="/tmp/newgen_snapshot_gap_status_${TEST_PORT}.json"
timeout 10 curl -sS "http://127.0.0.1:${TEST_PORT}/status" -o "$STATUS_FILE"   || fail "test node status did not respond on port $TEST_PORT"

TEST_HEIGHT="$(python3 - "$STATUS_FILE" <<'PYJSON'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    d=json.load(f)
print(int(d.get('height', 0)))
PYJSON
)"

MIN_TEST_HEIGHT=$(( PEER_HEIGHT > HEIGHT_LAG_TOLERANCE ? PEER_HEIGHT - HEIGHT_LAG_TOLERANCE : 0 ))
if [ "$TEST_HEIGHT" -lt "$MIN_TEST_HEIGHT" ]; then
  fail "test node did not bootstrap close to snapshot height: test_height=$TEST_HEIGHT peer_snapshot_height=$PEER_HEIGHT tolerance=$HEIGHT_LAG_TOLERANCE"
fi

TMP_LOG="/tmp/newgen_snapshot_gap_logs_${TEST_WINDOW}_$$.log"
tmux capture-pane -p -t "${SESSION}:${TEST_WINDOW}" -S -12000 > "$TMP_LOG" 2>&1   || fail "cannot capture tmux logs for ${SESSION}:${TEST_WINDOW}"

tmux capture-pane -p -t "${SESSION}:${PEER_WINDOW}" -S -12000 >> "$TMP_LOG" 2>&1 || true

if grep -Eiq 'event=large_gap_without_snapshot_bootstrap' "$TMP_LOG"; then
  grep -Ein 'event=large_gap_without_snapshot_bootstrap' "$TMP_LOG" | tail -20 >&2 || true
  fail "large-gap fallback was observed; snapshot bootstrap did not dominate"
fi

if ! grep -Eiq 'snapshot_import_applied|snapshot_import_ok|snapshot_v2.*import|source=seed_bundle|source=runtime_bundle|SnapshotV2Meta' "$TMP_LOG"; then
  tail -200 "$TMP_LOG" >&2 || true
  fail "no snapshot import/meta success signal found in logs"
fi

REMOTE_APPLIED_COUNT="$(grep -Eic 'RemoteApplied height=' "$TMP_LOG" || true)"
if [ "$REMOTE_APPLIED_COUNT" -gt "$MAX_REMOTE_APPLIED_LINES" ]; then
  fail "block-by-block replay appears dominant: RemoteApplied lines=$REMOTE_APPLIED_COUNT max=$MAX_REMOTE_APPLIED_LINES"
fi

echo "[PASS] snapshot large-gap bootstrap acceptance"
echo "peer_snapshot_height=$PEER_HEIGHT"
echo "test_node_height=$TEST_HEIGHT"
echo "remote_applied_lines=$REMOTE_APPLIED_COUNT"
echo "log_file=$TMP_LOG"
