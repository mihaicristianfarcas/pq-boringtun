#!/usr/bin/env bash
#
# prestage_mac.sh — one-command prep of the VPS demo from the Mac.
#
# Drives the VPS over SSH: syncs source, builds Linux binaries, brings up the
# three tunnels, runs the REAL cross-host ML-KEM-768 PSK exchange, then brings
# up the Mac side and forces a first handshake on each tunnel so everything is
# proven up before the talk.
#
# Required env:
#   DEMO_VPS_SSH    ssh target, e.g. ubuntu@203.0.113.9
#   DEMO_VPS_HOST   public IP/host the Mac points its endpoint at (often same)
# Optional:
#   DEMO_EGRESS_IFACE   physical iface (default en0)   DEMO_WORKDIR (default /tmp/pq-demo)
#
# Run as your NORMAL user (so ssh/scp/rsync use YOUR keys). The local tunnel
# commands are individually elevated with sudo and will prompt once:
#   DEMO_VPS_SSH=ubuntu@1.2.3.4 DEMO_VPS_HOST=1.2.3.4 ./prestage_mac.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="${DEMO_WORKDIR:-/tmp/pq-demo}"
VPS_SSH="${DEMO_VPS_SSH:?set DEMO_VPS_SSH (e.g. ubuntu@1.2.3.4)}"
VPS_HOST="${DEMO_VPS_HOST:?set DEMO_VPS_HOST (public IP the Mac dials)}"
VPS_SRC="/opt/pq-boringtun"
SUDO="${SUDO:-sudo}"   # local tunnel commands need root; ssh/scp/rsync do NOT
mkdir -p "$WORKDIR"

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, NOT root — otherwise ssh/scp would use root's keys." >&2
  exit 1
fi

# A prior `sudo local_fallback.sh` leaves WORKDIR root-owned; reclaim it so this
# user-run script can write keys/binaries there.
if [ ! -w "$WORKDIR" ]; then
  echo "Reclaiming $WORKDIR (root-owned from a prior sudo run)…"
  $SUDO chown -R "$(id -u):$(id -g)" "$WORKDIR"
fi

# name  iface  port   mac_ip       peer_ip      build    psk
ROWS=(
  "vanilla utun20 51820 10.13.0.1 10.13.0.2 vanilla no"
  "psk     utun21 51821 10.13.1.1 10.13.1.2 vanilla yes"
  "pq      utun22 51822 10.13.2.1 10.13.2.2 pq      no"
)
INTERFACES=(utun20 utun21 utun22)

# Clear stale boringtun on our Mac interfaces (e.g. left by cross_device_test_mac.sh,
# which also uses utun20/21) so the demo tunnels don't collide.
kill_iface_daemons() {
  for ifc in "${INTERFACES[@]}"; do
    $SUDO pkill -f "boringtun.* $ifc( |\$)" 2>/dev/null || true
  done
}

remote() { ssh "$VPS_SSH" "PQ_SRC=$VPS_SRC DEMO_WORKDIR=$WORKDIR bash $VPS_SRC/demo/vps/setup.sh $*"; }

echo "==> [1/7] Building Mac binaries"
cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" >/dev/null 2>&1
cp "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-vanilla"
cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" --features boringtun/pq >/dev/null 2>&1
cp "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-pq"
cargo build -p pq-psk-tool --manifest-path "$PROJECT_ROOT/Cargo.toml" >/dev/null 2>&1
cp "$PROJECT_ROOT/target/debug/pq-psk-tool" "$WORKDIR/pq-psk-tool"

echo "==> [2/7] Syncing source to VPS and provisioning"
ssh "$VPS_SSH" "sudo mkdir -p $VPS_SRC && sudo chown \$(id -u):\$(id -g) $VPS_SRC"
rsync -az --delete --exclude target --exclude .git --exclude '.venv' --exclude '__pycache__' \
  "$PROJECT_ROOT/" "$VPS_SSH:$VPS_SRC/"
remote provision

echo "==> [3/7] Generating Mac keypairs"
declare -A MACPUB
for row in "${ROWS[@]}"; do
  read -r name iface port mip pip build psk <<<"$row"
  wg genkey >"$WORKDIR/$name.mac.key"
  MACPUB[$name]=$(wg pubkey <"$WORKDIR/$name.mac.key")
done

echo "==> [4/7] Bringing up VPS tunnels"
MAC_VANILLA_PUB="${MACPUB[vanilla]}" MAC_PSK_PUB="${MACPUB[psk]}" MAC_PQ_PUB="${MACPUB[pq]}" \
  ssh "$VPS_SSH" "PQ_SRC=$VPS_SRC DEMO_WORKDIR=$WORKDIR \
    MAC_VANILLA_PUB=${MACPUB[vanilla]} MAC_PSK_PUB=${MACPUB[psk]} MAC_PQ_PUB=${MACPUB[pq]} \
    bash $VPS_SRC/demo/vps/setup.sh up"
remote pubkeys >"$WORKDIR/vps_pubkeys"

echo "==> [5/7] Cross-host ML-KEM-768 PSK exchange"
"$WORKDIR/pq-psk-tool" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
scp -q "$WORKDIR/mlkem_ek.b64" "$VPS_SSH:$WORKDIR/mlkem_ek.b64"
remote encaps
scp -q "$VPS_SSH:$WORKDIR/mlkem_ct.b64" "$WORKDIR/mlkem_ct.b64"
"$WORKDIR/pq-psk-tool" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.b64"
MAC_PSK_PUB="${MACPUB[psk]}" ssh "$VPS_SSH" "DEMO_WORKDIR=$WORKDIR MAC_PSK_PUB=${MACPUB[psk]} \
    bash $VPS_SRC/demo/vps/setup.sh psk-apply"

echo "==> [6/7] Bringing up Mac tunnels"
kill_iface_daemons; sleep 1
for row in "${ROWS[@]}"; do
  read -r name iface port mip pip build psk <<<"$row"
  bin="$WORKDIR/boringtun-$build"
  vpspub=$(awk -v n="$name" '$1==n{print $2}' "$WORKDIR/vps_pubkeys")
  echo "$vpspub" >"$WORKDIR/$name.peerpub"   # orchestrator uses this to re-handshake

  $SUDO "$bin" "$iface" --foreground --disable-drop-privileges 2>"$WORKDIR/$name.mac.log" &
  mpid=$!; echo "$mpid" >"$WORKDIR/$name.mac.pid"; sleep 1
  kill -0 "$mpid" 2>/dev/null || { echo "ERROR: $name daemon for $iface exited — is $iface already in use? (ifconfig $iface; pgrep -fl $iface)"; exit 1; }

  psk_args=(); [ "$psk" = "yes" ] && psk_args=(preshared-key "$WORKDIR/psk.b64")
  $SUDO wg set "$iface" private-key "$WORKDIR/$name.mac.key" listen-port "$port" \
      peer "$vpspub" "${psk_args[@]}" endpoint "$VPS_HOST:$port" allowed-ips "$pip/32"
  $SUDO ifconfig "$iface" "$mip" "$pip"
  echo "  $name: $iface=$mip -> $VPS_HOST:$port (peer $pip)"
done

echo "==> [7/7] Forcing first handshakes"
for row in "${ROWS[@]}"; do
  read -r name _ _ _ pip _ _ <<<"$row"
  ping -c 1 -t 2 "$pip" >/dev/null 2>&1 && echo "  $name: handshake OK ($pip)" \
    || echo "  $name: ping failed — see $WORKDIR/$name.mac.log"
done

echo
echo "Prestaged. Start the UI:"
echo "  cd demo/backend && uv run python app.py --vps-host $VPS_HOST --egress-iface ${DEMO_EGRESS_IFACE:-en0}"
