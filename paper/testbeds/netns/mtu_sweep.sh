#!/usr/bin/env bash
#
# Experiment #1 — MTU / fragmentation behaviour
#
# Sweeps path MTU (and an optional fragment-dropping middlebox rule) across
# both vanilla and hybrid (pq) WireGuard. Reports per-cell handshake success
# rate and median first-packet latency.
#
# Output: paper/measurements/netns-mtu-sweep.csv
#
# CSV schema:
#   mode,mtu,drop_frags,trials,successes,success_rate,p50_rtt_ms
#
# Approximate runtime: 3 MTU values × 2 frag modes × 2 wg modes ×
#                      10 trials × ~6 s/trial ≈ 12 min.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ----- Configuration --------------------------------------------------------

# Path MTU sweep. The hybrid initiation is 1332 bytes and the response is
# 1180 bytes. Values straddle the fragmentation boundary:
#   1500 — standard Ethernet, no fragmentation expected for any mode
#   1400 — common PPPoE/VPN-in-VPN value, still above hybrid messages
#   1300 — fragments the hybrid initiation (1332 > 1300)
#   1280 — IPv6 minimum, fragments both hybrid messages
MTUS=(1500 1400 1300 1280)

# Both with and without a fragment-dropping middlebox rule on the responder.
DROP_MODES=("" "drop_frags")

# Modes to test.
WG_MODES=(vanilla pq)

TRIALS_PER_CELL=10

OUT_CSV="$REPO_ROOT/paper/measurements/netns-mtu-sweep.csv"

# ----- Run -----------------------------------------------------------------

require_root
build_binaries

mkdir -p "$(dirname "$OUT_CSV")"
echo "mode,mtu,drop_frags,trials,successes,success_rate,p50_rtt_ms" > "$OUT_CSV"

for mtu in "${MTUS[@]}"; do
    for drop in "${DROP_MODES[@]}"; do
        for mode in "${WG_MODES[@]}"; do
            log "=== cell: mtu=$mtu drop=${drop:-no} mode=$mode ==="

            setup_netns "$mtu" "$drop"
            read -r INIT_PID RESP_PID <<<"$(start_tunnels "$mode")"

            successes=0
            rtts=()
            for i in $(seq 1 "$TRIALS_PER_CELL"); do
                # Each trial needs a fresh tunnel because the first packet
                # triggers the handshake; subsequent pings would skip it.
                if [[ $i -gt 1 ]]; then
                    stop_tunnels "$INIT_PID" "$RESP_PID"
                    read -r INIT_PID RESP_PID <<<"$(start_tunnels "$mode")"
                fi
                result=$(attempt_handshake)
                ok=${result%%,*}
                rtt=${result##*,}
                if [[ "$ok" == "1" ]]; then
                    successes=$((successes + 1))
                    rtts+=("$rtt")
                fi
            done

            stop_tunnels "$INIT_PID" "$RESP_PID"

            # p50 of successful RTTs (NaN if none).
            if [[ ${#rtts[@]} -eq 0 ]]; then
                p50="NaN"
            else
                p50=$(printf '%s\n' "${rtts[@]}" | sort -n | \
                    awk -v n=${#rtts[@]} 'NR==int((n+1)/2){print; exit}')
            fi
            rate=$(awk -v s=$successes -v t=$TRIALS_PER_CELL \
                'BEGIN{printf "%.2f", s/t}')

            drop_label=${drop:-none}
            echo "$mode,$mtu,$drop_label,$TRIALS_PER_CELL,$successes,$rate,$p50" \
                | tee -a "$OUT_CSV"
        done
    done
done

teardown_netns
log "DONE. Results: $OUT_CSV"
