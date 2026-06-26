#!/usr/bin/env bash
#
# local_fallback.sh — bring up all three demo tunnels on THIS Mac over loopback.
#
# This is the bullet-proof fallback for an unstable defense-room network, and
# the only path you can rehearse without a VPS. Each variant is a pair of
# boringtun interfaces on localhost (mirrors `pq-hybrid-test.sh compare`).
#
#   sudo ./local_fallback.sh up      # build, start tunnels + receiver
#   sudo ./local_fallback.sh down    # tear everything down
#
# Then run the backend in local mode (NO sudo needed for the server itself if
# you grant passwordless sudo for wg/tcpdump/ifconfig — see README):
#
#   python demo/backend/app.py --local
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="${DEMO_WORKDIR:-/tmp/pq-demo}"
RECEIVER_PORT="${DEMO_RECEIVER_PORT:-8765}"
mkdir -p "$WORKDIR"

# variant   mac_if  peer_if  mac_port peer_port  mac_ip       peer_ip      build    psk
ROWS=(
  "vanilla  utun20  utun30   51820    51830      10.13.0.1    10.13.0.2    vanilla  no"
  "psk      utun21  utun31   51821    51831      10.13.1.1    10.13.1.2    vanilla  yes"
  "pq       utun22  utun32   51822    51832      10.13.2.1    10.13.2.2    pq       no"
)

require_root() {
  if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 1; fi
}

build_binaries() {
  echo "--- Building boringtun (vanilla + pq) and pq-psk-tool ---"
  cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" >/dev/null 2>&1
  cp "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-vanilla"
  cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" --features boringtun/pq >/dev/null 2>&1
  cp "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-pq"
  cargo build -p pq-psk-tool --manifest-path "$PROJECT_ROOT/Cargo.toml" >/dev/null 2>&1
  cp "$PROJECT_ROOT/target/debug/pq-psk-tool" "$WORKDIR/pq-psk-tool"
}

mlkem_psk() {
  # Faithful local ML-KEM-768 exchange → 32-byte PSK in $WORKDIR/psk.b64
  echo "--- ML-KEM-768 PSK exchange (local) ---"
  "$WORKDIR/pq-psk-tool" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
  "$WORKDIR/pq-psk-tool" encaps "$WORKDIR/mlkem_ek.b64" -c "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.b64"
  "$WORKDIR/pq-psk-tool" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk_verify.b64"
  diff -q "$WORKDIR/psk.b64" "$WORKDIR/psk_verify.b64" >/dev/null
}

up() {
  require_root
  build_binaries
  mlkem_psk

  echo "--- Starting tunnels ---"
  for row in "${ROWS[@]}"; do
    read -r name mif pif mport pport mip pip build psk <<<"$row"
    bin="$WORKDIR/boringtun-$build"

    # keypairs
    mpriv=$(wg genkey); mpub=$(echo "$mpriv" | wg pubkey)
    ppriv=$(wg genkey); ppub=$(echo "$ppriv" | wg pubkey)
    echo "$mpriv" >"$WORKDIR/$name.mac.key"
    echo "$ppriv" >"$WORKDIR/$name.peer.key"
    # the orchestrator forces handshakes by re-adding THIS peer:
    echo "$ppub" >"$WORKDIR/$name.peerpub"

    # daemons
    WG_LOG_LEVEL=debug "$bin" "$mif" --foreground --disable-drop-privileges 2>"$WORKDIR/$name.mac.log" &
    echo $! >"$WORKDIR/$name.mac.pid"; sleep 1
    WG_LOG_LEVEL=debug "$bin" "$pif" --foreground --disable-drop-privileges 2>"$WORKDIR/$name.peer.log" &
    echo $! >"$WORKDIR/$name.peer.pid"; sleep 1

    # config (PSK only on the psk variant)
    psk_args=(); [ "$psk" = "yes" ] && psk_args=(preshared-key "$WORKDIR/psk.b64")
    wg set "$mif" private-key "$WORKDIR/$name.mac.key" listen-port "$mport" \
        peer "$ppub" "${psk_args[@]}" endpoint "127.0.0.1:$pport" allowed-ips "$pip/32"
    wg set "$pif" private-key "$WORKDIR/$name.peer.key" listen-port "$pport" \
        peer "$mpub" "${psk_args[@]}" endpoint "127.0.0.1:$mport" allowed-ips "$mip/32"

    ifconfig "$mif" "$mip" "$pip"
    ifconfig "$pif" "$pip" "$mip"
    echo "  $name: $mif=$mip  <->  $pif=$pip   (build=$build psk=$psk)"
  done

  echo "--- Starting receiver on 0.0.0.0:$RECEIVER_PORT ---"
  python3 "$PROJECT_ROOT/demo/vps/receiver.py" --port "$RECEIVER_PORT" \
      >"$WORKDIR/receiver.log" 2>&1 &
  echo $! >"$WORKDIR/receiver.pid"

  echo "--- Forcing first handshakes ---"
  for row in "${ROWS[@]}"; do
    read -r name _ _ _ _ _ pip _ _ <<<"$row"
    ping -c 1 "$pip" >/dev/null 2>&1 && echo "  $name: handshake OK ($pip)" \
      || echo "  $name: ping failed (check $WORKDIR/$name.mac.log)"
  done
  echo "Local fallback up. Start the UI:  python demo/backend/app.py --local"
}

down() {
  require_root
  echo "--- Tearing down ---"
  for f in "$WORKDIR"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  done
  for row in "${ROWS[@]}"; do
    read -r _ mif pif _ _ _ _ _ _ <<<"$row"
    ifconfig "$mif" down 2>/dev/null || true
    ifconfig "$pif" down 2>/dev/null || true
  done
  rm -f "$WORKDIR"/*.key "$WORKDIR"/*.log "$WORKDIR"/mlkem_*.b64 "$WORKDIR"/psk*.b64 "$WORKDIR"/*.peerpub
  echo "Done."
}

case "${1:-up}" in
  up)   up ;;
  down) down ;;
  *)    echo "usage: $0 {up|down}"; exit 1 ;;
esac
