#!/usr/bin/env bash
#
# smoke_test.sh — verify all three tunnels carry traffic and the receiver
# answers through each. Run after prestage_mac.sh (VPS mode) or
# local_fallback.sh up (loopback mode). Works the same either way: it only
# talks to the tunnel IPs.
#
set -uo pipefail
RECVPORT="${DEMO_RECEIVER_PORT:-8765}"

# name  peer_ip
ROWS=(
  "vanilla 10.13.0.2"
  "psk     10.13.1.2"
  "pq      10.13.2.2"
)

fail=0
printf "%-9s %-7s %-9s\n" "variant" "ping" "receiver"
for row in "${ROWS[@]}"; do
  read -r name pip <<<"$row"
  if ping -c 1 "$pip" >/dev/null 2>&1; then p=PASS; else p=FAIL; fail=1; fi
  if curl -s --max-time 5 "http://$pip:$RECVPORT/health" | grep -q "up"; then r=PASS; else r=FAIL; fail=1; fi
  printf "%-9s %-7s %-9s\n" "$name" "$p" "$r"
done

echo
if [ "$fail" -eq 0 ]; then
  echo "All tunnels + receiver healthy. Ready to demo."
else
  echo "Something is down — check \$DEMO_WORKDIR/*.log before the talk."
  exit 1
fi
