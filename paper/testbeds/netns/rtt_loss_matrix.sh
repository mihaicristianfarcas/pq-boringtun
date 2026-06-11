#!/usr/bin/env bash
#
# Experiment #2 — RTT and loss interaction with the hybrid handshake
#
# Sweeps a matrix of injected one-way delay and packet loss across both
# vanilla and hybrid WireGuard, MTU pinned at 1500 (no fragmentation
# pressure — we want to isolate the RTT/loss signal here, not entangle
# it with experiment #1).
#
# The interesting hypothesis: at non-trivial loss rates, the larger
# hybrid handshake messages take a disproportionate hit because a single
# dropped fragment kills the whole exchange. We verify this on the way.
#
# Output: paper/measurements/netns-rtt-loss-matrix.csv
#
# CSV schema:
#   mode,delay_ms,loss_pct,trials,successes,success_rate,
#       p50_rtt_ms,p95_rtt_ms
#
# Approximate runtime: 4 RTTs × 3 loss values × 2 modes × 20 trials ×
#                       worst case ~3 s = ~25 min.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ----- Configuration --------------------------------------------------------

# One-way delay applied symmetrically (egress in both netns). Real RTT
# observed at the application = 2 × delay + small kernel/scheduling jitter.
DELAYS_MS=(0 10 50 100)

# Packet loss applied symmetrically on each direction's egress qdisc.
# 0.1 % is the noise floor of a clean wired LAN; 1 % is a stressed mobile
# or congested edge link.
LOSS_PCTS=(0 0.1 1)

WG_MODES=(vanilla pq)

# Pin MTU to 1500; we are not testing fragmentation here.
PATH_MTU=1500

TRIALS_PER_CELL=20

OUT_CSV="$REPO_ROOT/paper/measurements/netns-rtt-loss-matrix.csv"

# ----- Helpers --------------------------------------------------------------

p95() {
    local n=$1; shift
    if [[ $n -eq 0 ]]; then echo NaN; return; fi
    local k=$(( (n * 95 + 99) / 100 ))   # ceil(0.95 * n)
    printf '%s\n' "$@" | sort -n | awk -v k="$k" 'NR==k{print; exit}'
}

p50() {
    local n=$1; shift
    if [[ $n -eq 0 ]]; then echo NaN; return; fi
    local k=$(( (n + 1) / 2 ))
    printf '%s\n' "$@" | sort -n | awk -v k="$k" 'NR==k{print; exit}'
}

# ----- Run -----------------------------------------------------------------

require_root
require_deps
build_binaries

mkdir -p "$(dirname "$OUT_CSV")"
echo "mode,delay_ms,loss_pct,trials,successes,success_rate,p50_rtt_ms,p95_rtt_ms" \
    > "$OUT_CSV"

for delay in "${DELAYS_MS[@]}"; do
    for loss in "${LOSS_PCTS[@]}"; do
        for mode in "${WG_MODES[@]}"; do
            log "=== cell: delay=${delay}ms loss=${loss}% mode=$mode ==="

            setup_netns "$PATH_MTU" ""

            # Apply netem on both veth endpoints (symmetric path conditions).
            add_netem "$NS_INIT" "$VETH_INIT" "$delay" "$loss"
            add_netem "$NS_RESP" "$VETH_RESP" "$delay" "$loss"

            successes=0
            rtts=()
            for i in $(seq 1 "$TRIALS_PER_CELL"); do
                read -r INIT_PID RESP_PID <<<"$(start_tunnels "$mode")"
                result=$(attempt_handshake)
                ok=${result%%,*}
                rtt=${result##*,}
                if [[ "$ok" == "1" ]]; then
                    successes=$((successes + 1))
                    rtts+=("$rtt")
                fi
                stop_tunnels "$INIT_PID" "$RESP_PID"
            done

            n=${#rtts[@]}
            rate=$(awk -v s=$successes -v t=$TRIALS_PER_CELL \
                'BEGIN{printf "%.2f", s/t}')
            median=$(p50 "$n" "${rtts[@]+"${rtts[@]}"}")
            tail=$(p95 "$n" "${rtts[@]+"${rtts[@]}"}")

            echo "$mode,$delay,$loss,$TRIALS_PER_CELL,$successes,$rate,$median,$tail" \
                | tee -a "$OUT_CSV"
        done
    done
done

teardown_netns
log "DONE. Results: $OUT_CSV"
