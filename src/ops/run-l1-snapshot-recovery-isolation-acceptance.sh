#!/usr/bin/env bash
set -euo pipefail

# NewGen L1 snapshot recovery isolation acceptance check.
#
# Purpose:
#   Verify that A/B/C stay operational while a recovery node (D by default)
#   is in cold-start snapshot / restart-catchup. The script is intentionally
#   non-destructive: it does not reset data and it does not start/stop tmux.
#
# Defaults match the server layout used by the private NewGen L1 chain:
#   A/B/C API ports: 8001,8002,8003
#   D API port:     8004 (override if your D port is different)
#
# Optional environment:
#   NEWGEN_CHAIN_ROOT=/srv/newgen/chain
#   NEWGEN_ABC_PORTS="8001 8002 8003"
#   NEWGEN_RECOVERY_PORT=8004
#   NEWGEN_ACCEPTANCE_ROUNDS=12
#   NEWGEN_ACCEPTANCE_SLEEP_SEC=5
#   NEWGEN_REQUIRE_RECOVERY_NON_OPERATIONAL=1
#
# PASS criteria:
#   - A/B/C /status respond for every round;
#   - A/B/C heights advance during the window;
#   - A/B/C keep consensus/quorum/p2p/proposal readiness healthy when fields exist;
#   - recovery node, when reachable, is not counted as operational before admission.

ROOT="${NEWGEN_CHAIN_ROOT:-/srv/newgen/chain}"
ABC_PORTS="${NEWGEN_ABC_PORTS:-8001 8002 8003}"
RECOVERY_PORT="${NEWGEN_RECOVERY_PORT:-8004}"
ROUNDS="${NEWGEN_ACCEPTANCE_ROUNDS:-12}"
SLEEP_SEC="${NEWGEN_ACCEPTANCE_SLEEP_SEC:-5}"
REQUIRE_RECOVERY_NON_OPERATIONAL="${NEWGEN_REQUIRE_RECOVERY_NON_OPERATIONAL:-1}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

need curl
need python3

cd "$ROOT" 2>/dev/null || true

TMP_DIR="/tmp/newgen_l1_snapshot_recovery_isolation_$$"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

fetch_status() {
  local port="$1"
  local out="$2"
  timeout 5 curl -fsS "http://127.0.0.1:${port}/status" -o "$out"
}

json_field() {
  local file="$1"
  local key="$2"
  python3 - "$file" "$key" <<'PYJSON'
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    with open(path, 'r', encoding='utf-8') as f:
        d = json.load(f)
except Exception:
    print("")
    raise SystemExit(0)
cur = d
for part in key.split('.'):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("")
        raise SystemExit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PYJSON
}

status_bool_ok_or_absent() {
  local file="$1"
  local key="$2"
  local value
  value="$(json_field "$file" "$key")"
  [ -z "$value" ] || [ "$value" = "true" ]
}

status_bool_false_or_absent() {
  local file="$1"
  local key="$2"
  local value
  value="$(json_field "$file" "$key")"
  [ -z "$value" ] || [ "$value" = "false" ]
}

declare -A first_height=()
declare -A last_height=()
declare -A saw_status=()

echo "[INFO] monitoring A/B/C ports: $ABC_PORTS"
echo "[INFO] recovery port: $RECOVERY_PORT rounds=$ROUNDS sleep=${SLEEP_SEC}s"

for round in $(seq 1 "$ROUNDS"); do
  echo "[INFO] round=$round"
  for port in $ABC_PORTS; do
    file="$TMP_DIR/status_${port}_${round}.json"
    fetch_status "$port" "$file" || fail "A/B/C status failed on port=$port round=$round"
    saw_status[$port]=1
    height="$(json_field "$file" height)"
    finalized="$(json_field "$file" finalized_height)"
    [ -n "$height" ] || fail "missing height on port=$port round=$round"
    [ "$height" -gt 0 ] || fail "invalid height=$height on port=$port round=$round"
    if [ -z "${first_height[$port]:-}" ]; then
      first_height[$port]="$height"
    fi
    last_height[$port]="$height"

    status_bool_ok_or_absent "$file" consensus_ready || fail "consensus_ready=false on port=$port round=$round"
    status_bool_ok_or_absent "$file" p2p_ready_for_mining || fail "p2p_ready_for_mining=false on port=$port round=$round"
    status_bool_ok_or_absent "$file" proposal_gate_open || fail "proposal_gate_open=false on port=$port round=$round"
    status_bool_ok_or_absent "$file" operational_runtime_quorum_ready || fail "operational_runtime_quorum_ready=false on port=$port round=$round"

    quorum="$(json_field "$file" operational_runtime_quorum_ready)"
    p2p="$(json_field "$file" p2p_ready_for_mining)"
    proposal="$(json_field "$file" proposal_gate_open)"
    echo "  port=$port height=$height finalized=${finalized:-unknown} quorum=${quorum:-absent} p2p=${p2p:-absent} proposal=${proposal:-absent}"
  done

  recovery_file="$TMP_DIR/status_recovery_${round}.json"
  if fetch_status "$RECOVERY_PORT" "$recovery_file" 2>/dev/null; then
    recovery_height="$(json_field "$recovery_file" height)"
    recovery_boot="$(json_field "$recovery_file" runtime_bootstrap_complete)"
    recovery_caught="$(json_field "$recovery_file" runtime_sync_caught_up)"
    recovery_p2p="$(json_field "$recovery_file" p2p_ready_for_mining)"
    recovery_quorum="$(json_field "$recovery_file" operational_runtime_quorum_ready)"
    recovery_phase="$(json_field "$recovery_file" boot_phase)"
    echo "  recovery port=$RECOVERY_PORT height=${recovery_height:-unknown} boot=${recovery_boot:-absent} caught=${recovery_caught:-absent} p2p=${recovery_p2p:-absent} quorum=${recovery_quorum:-absent} phase=${recovery_phase:-absent}"

    if [ "$REQUIRE_RECOVERY_NON_OPERATIONAL" = "1" ]; then
      # A recovery node must not expose proposal readiness while it is still
      # missing bootstrap/catchup completion. Once it is fully admitted, this
      # script focuses on the A/B/C isolation invariant.
      if [ "${recovery_boot:-}" != "true" ] || [ "${recovery_caught:-}" != "true" ]; then
        status_bool_false_or_absent "$recovery_file" proposal_gate_open || fail "recovery node proposal_gate_open=true before bootstrap/catchup admission round=$round"
      fi
    fi
  else
    echo "  recovery port=$RECOVERY_PORT status=unreachable_or_not_started"
  fi

  if [ "$round" -lt "$ROUNDS" ]; then
    sleep "$SLEEP_SEC"
  fi
done

for port in $ABC_PORTS; do
  [ "${saw_status[$port]:-0}" = "1" ] || fail "no status collected for port=$port"
  start="${first_height[$port]}"
  end="${last_height[$port]}"
  if [ "$end" -le "$start" ]; then
    fail "A/B/C did not advance on port=$port start_height=$start end_height=$end"
  fi
  echo "[OK] port=$port advanced start_height=$start end_height=$end delta=$((end - start))"
done

echo "[PASS] snapshot recovery isolation acceptance: A/B/C stayed operational while recovery peer was isolated"
