#!/usr/bin/env bash
#
# Experiment #3 — DoS asymmetry: how expensive is it for a responder to
# process a flood of handshake init packets, vanilla vs hybrid, and does
# the MAC1 check short-circuit before Encaps as the WireGuard design
# intends?
#
# Methodology:
#   - Bring up a single responder boringtun-cli in ns-resp.
#   - From ns-init, run the handshake_flood example for $DURATION seconds
#     at $TARGET_PPS pps. The flood emits init packets with fresh keypairs
#     so the responder cannot session-cache them.
#   - Measure responder CPU time consumed during the flood by diffing
#     /proc/<pid>/stat (user + sys ticks). Normalise by packets sent.
#
# Two MAC1 modes:
#   valid    — flooder uses the real responder pubkey, so MAC1 matches.
#              Responder must run full crypto (Encaps in pq mode).
#   invalid  — MAC1 byte is flipped after format. Responder should reject
#              before any Encaps work happens.
#
# The interesting comparison is (mode × mac1):
#     vanilla / invalid : baseline; reject-cheap path
#     pq      / invalid : same reject path, same cost as vanilla expected
#     vanilla / valid   : full classical handshake processing
#     pq      / valid   : full hybrid handshake — Encaps cost amplified
#
# Output: paper/measurements/netns-dos-flood.csv
#
# CSV schema:
#   mode,mac1,target_pps,duration_sec,packets_sent,
#       cpu_sec,cpu_per_pkt_us

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ----- Configuration --------------------------------------------------------

DURATION_SEC=10
# 0 = unbounded (saturate). Use a positive int to cap the flood.
TARGET_PPS=0

WG_MODES=(vanilla pq)
MAC1_MODES=(invalid valid)

OUT_CSV="$REPO_ROOT/paper/measurements/netns-dos-flood.csv"

CLK_TCK=$(getconf CLK_TCK)

# ----- Helpers --------------------------------------------------------------

# Read cumulative user + sys ticks from /proc/<pid>/stat. The 14th and 15th
# whitespace-separated fields are utime, stime (clock ticks). Field 2 is the
# comm in parens and may contain spaces — strip it first.
read_proc_cpu_ticks() {
    local pid="$1"
    [[ -r /proc/$pid/stat ]] || { echo "0"; return; }
    local raw
    raw=$(< "/proc/$pid/stat")
    # Drop "(comm)" — replace everything between first '(' and last ')' with one
    # token "X", so field positions are stable.
    local after_comm="${raw#*) }"
    # After comm, fields are 0-indexed starting at state. utime is original
    # field 14, stime is 15; we removed pid + comm (2 fields), so they are now
    # at positions 12 (zero-indexed: 11) and 13 (12) of the remaining tokens.
    read -ra fields <<<"$after_comm"
    echo $(( fields[11] + fields[12] ))
}

# ----- Build the flood binary in both feature modes ------------------------

build_flood_binaries() {
    log "building handshake_flood (vanilla + pq)"
    (
        cd "$REPO_ROOT"
        CARGO_TARGET_DIR="$REPO_ROOT/target/release-vanilla" \
            cargo build --release -p boringtun --example handshake_flood >/dev/null
        CARGO_TARGET_DIR="$REPO_ROOT/target/release-pq" \
            cargo build --release -p boringtun --example handshake_flood --features pq >/dev/null
    )
}
FLOOD_BIN_VANILLA="$REPO_ROOT/target/release-vanilla/release/examples/handshake_flood"
FLOOD_BIN_PQ="$REPO_ROOT/target/release-pq/release/examples/handshake_flood"

# ----- Run -----------------------------------------------------------------

require_root
require_deps
build_binaries
build_flood_binaries

mkdir -p "$(dirname "$OUT_CSV")"
echo "mode,mac1,target_pps,duration_sec,packets_sent,cpu_sec,cpu_per_pkt_us" \
    > "$OUT_CSV"

for mode in "${WG_MODES[@]}"; do
    for mac1 in "${MAC1_MODES[@]}"; do
        log "=== cell: mode=$mode mac1=$mac1 ==="

        # Standard MTU, no impairment — we are stressing the CPU, not the path.
        setup_netns 1500 ""

        # Bring up only the responder; we do not want a real initiator
        # competing for the same wg interface.
        local_resp_priv=$(wg genkey)
        local_resp_pub=$(echo "$local_resp_priv" | wg pubkey)

        bin=$([[ $mode == "pq" ]] && echo "$BIN_PQ" || echo "$BIN_VANILLA")
        flood_bin=$([[ $mode == "pq" ]] && echo "$FLOOD_BIN_PQ" || echo "$FLOOD_BIN_VANILLA")

        ip netns exec "$NS_RESP" \
            "$bin" "$WG_IFACE_RESP" --foreground --disable-drop-privileges \
            >/tmp/pqwg-"$mode"-resp.log 2>&1 &
        RESP_PID=$!

        # Wait for the wg interface to appear.
        for i in {1..50}; do
            ip netns exec "$NS_RESP" ip link show "$WG_IFACE_RESP" >/dev/null 2>&1 && break
            sleep 0.1
        done

        echo "$local_resp_priv" | ip netns exec "$NS_RESP" wg set "$WG_IFACE_RESP" \
            private-key /dev/stdin listen-port "$RESP_PORT"

        # Sample CPU ticks before the flood. Wait briefly so any setup CPU
        # has been billed.
        sleep 0.5
        ticks_before=$(read_proc_cpu_ticks "$RESP_PID")

        # Run the flood. handshake_flood prints `packets_sent=N elapsed=... pps=...`.
        out=$(ip netns exec "$NS_INIT" \
            "$flood_bin" "$UNDERLAY_RESP_IP:$RESP_PORT" \
            "$local_resp_pub" "$DURATION_SEC" "$TARGET_PPS" "$mac1")
        sleep 0.5
        ticks_after=$(read_proc_cpu_ticks "$RESP_PID")

        packets_sent=$(echo "$out" | sed -n 's/.*packets_sent=\([0-9]*\).*/\1/p')
        ticks_delta=$((ticks_after - ticks_before))
        cpu_sec=$(awk -v t=$ticks_delta -v c=$CLK_TCK 'BEGIN{printf "%.3f", t/c}')
        if [[ "$packets_sent" -gt 0 ]]; then
            cpu_per_pkt_us=$(awk -v c=$cpu_sec -v n=$packets_sent \
                'BEGIN{printf "%.2f", c * 1e6 / n}')
        else
            cpu_per_pkt_us="NaN"
        fi

        kill "$RESP_PID" 2>/dev/null || true
        wait "$RESP_PID" 2>/dev/null || true

        echo "$mode,$mac1,$TARGET_PPS,$DURATION_SEC,$packets_sent,$cpu_sec,$cpu_per_pkt_us" \
            | tee -a "$OUT_CSV"
    done
done

teardown_netns
log "DONE. Results: $OUT_CSV"
