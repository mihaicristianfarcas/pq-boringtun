#!/usr/bin/env bash
#
# setup.sh — VPS (Linux) side of the demo. Run on the VPS, usually driven over
# SSH by scripts/prestage_mac.sh. The VPS is the RESPONDER for all three
# tunnels (no endpoint configured — it learns the Mac's endpoint from the
# incoming handshake), and hosts the echo+checksum receiver.
#
# Subcommands:
#   provision        install deps, build boringtun (vanilla+pq) + pq-psk-tool
#   up               bring up wgv/wgp/wgq (needs MAC_*_PUB env), start receiver
#   encaps           ML-KEM encaps step (reads mlkem_ek.b64, writes ct + psk)
#   psk-apply        apply $WORK/psk.b64 to the PSK tunnel
#   pubkeys          print the three VPS public keys
#   down             tear everything down
#
set -euo pipefail

SRC="${PQ_SRC:-/opt/pq-boringtun}"
WORK="${DEMO_WORKDIR:-/tmp/pq-demo}"
RECVPORT="${DEMO_RECEIVER_PORT:-8765}"
mkdir -p "$WORK"

# name  iface  port   vps_ip       mac_ip       build    psk
ROWS=(
  "vanilla wgv 51820 10.13.0.2 10.13.0.1 vanilla no"
  "psk     wgp 51821 10.13.1.2 10.13.1.1 vanilla yes"
  "pq      wgq 51822 10.13.2.2 10.13.2.1 pq      no"
)

# Atomic binary install. NEVER cp over a binary in place: if a boringtun daemon
# from a previous run is still executing $dst, Linux refuses the overwrite with
# ETXTBSY ("Text file busy"). Copy beside the target, then rename over it — the
# live daemon keeps its now-unlinked inode, the new binary takes the name.
install_bin() { cp "$1" "$2.new" && mv -f "$2.new" "$2"; }

# Kill boringtun daemons + receiver left by a previous run so (a) their open
# binary files are released before we rebuild over them and (b) their UDP ports
# and tun interfaces are freed.
kill_daemons() {
  pkill -f "receiver.py" 2>/dev/null || true
  for ifc in wgv wgp wgq; do sudo pkill -f "boringtun.* $ifc( |\$)" 2>/dev/null || true; done
}

provision() {
  echo "--- Installing dependencies ---"
  if command -v apt-get >/dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y wireguard-tools python3 curl build-essential pkg-config
  elif command -v dnf >/dev/null; then
    sudo dnf update -y
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y wireguard-tools python3 curl pkgconfig
  fi
  if ! command -v cargo >/dev/null; then
    echo "--- Installing Rust ---"
    curl -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  [ -e /dev/net/tun ] || { sudo modprobe tun || true; }

  echo "--- Building binaries from $SRC (native arch) ---"
  # Release the old binaries first (a live daemon -> "Text file busy" on copy),
  # then install atomically so even a surviving daemon can't block the rebuild.
  kill_daemons
  sleep 1
  cargo build -p boringtun-cli --manifest-path "$SRC/Cargo.toml" >/dev/null
  install_bin "$SRC/target/debug/boringtun-cli" "$WORK/boringtun-vanilla"
  cargo build -p boringtun-cli --manifest-path "$SRC/Cargo.toml" --features boringtun/pq >/dev/null
  install_bin "$SRC/target/debug/boringtun-cli" "$WORK/boringtun-pq"
  cargo build -p pq-psk-tool --manifest-path "$SRC/Cargo.toml" >/dev/null
  install_bin "$SRC/target/debug/pq-psk-tool" "$WORK/pq-psk-tool"
  echo "Provision complete."
}

mac_pub_for() {
  case "$1" in
    vanilla) echo "${MAC_VANILLA_PUB:?set MAC_VANILLA_PUB}";;
    psk)     echo "${MAC_PSK_PUB:?set MAC_PSK_PUB}";;
    pq)      echo "${MAC_PQ_PUB:?set MAC_PQ_PUB}";;
  esac
}

up() {
  echo "--- Bringing up VPS tunnels (responder) ---"
  : >"$WORK/vps_pubkeys"
  echo "--- Clearing any stale boringtun daemons ---"
  kill_daemons
  sleep 1
  for row in "${ROWS[@]}"; do
    read -r name iface port vip mip build psk <<<"$row"
    bin="$WORK/boringtun-$build"

    # stable VPS keypair per tunnel (reused across re-runs). umask 0600 the key
    # so `wg genkey` doesn't warn about a world-readable secret.
    if [ ! -f "$WORK/$name.vps.key" ]; then
      ( umask 077; wg genkey >"$WORK/$name.vps.key" )
      wg pubkey <"$WORK/$name.vps.key" >"$WORK/$name.vps.pub"
    fi
    echo "$name $(cat "$WORK/$name.vps.pub")" >>"$WORK/vps_pubkeys"

    # WG_LOG_FILE keeps each daemon's log in its own file (the default is a
    # single /tmp/boringtun.out the three would clobber); info level keeps it to
    # startup + timeouts/errors, not the per-packet handshake/keepalive spam.
    sudo env WG_LOG_LEVEL="${WG_LOG_LEVEL:-info}" WG_LOG_FILE="$WORK/$name.vps.log" \
        "$bin" "$iface" --disable-drop-privileges >>"$WORK/$name.vps.boot.log" 2>&1 &
    sleep 1
    # boringtun daemonises on Linux, so the launcher returns immediately by
    # design — verify the INTERFACE exists rather than the parent pid.
    ip link show "$iface" >/dev/null 2>&1 || { echo "ERROR: $name daemon did not create $iface — see $WORK/$name.vps.log"; exit 1; }

    psk_args=(); [ "$psk" = "yes" ] && [ -f "$WORK/psk.b64" ] && psk_args=(preshared-key "$WORK/psk.b64")
    sudo wg set "$iface" private-key "$WORK/$name.vps.key" listen-port "$port" \
        peer "$(mac_pub_for "$name")" "${psk_args[@]}" allowed-ips "$mip/32"
    sudo ip addr add "$vip/24" dev "$iface" 2>/dev/null || true
    sudo ip link set "$iface" up
    echo "  $name: $iface=$vip listening :$port (build=$build psk=$psk)"
  done

  echo "--- Starting receiver on 0.0.0.0:$RECVPORT ---"
  pkill -f "receiver.py" 2>/dev/null || true
  nohup python3 "$(dirname "$0")/receiver.py" --port "$RECVPORT" >"$WORK/receiver.log" 2>&1 &
  echo "VPS up."
}

encaps() {
  "$WORK/pq-psk-tool" encaps "$WORK/mlkem_ek.b64" -c "$WORK/mlkem_ct.b64" -p "$WORK/psk.b64"
  echo "encaps done: ct at $WORK/mlkem_ct.b64, psk at $WORK/psk.b64"
}

psk_apply() {
  sudo wg set wgp peer "${MAC_PSK_PUB:?set MAC_PSK_PUB}" preshared-key "$WORK/psk.b64"
  echo "PSK applied to wgp."
}

pubkeys() { cat "$WORK/vps_pubkeys"; }

down() {
  kill_daemons
  for row in "${ROWS[@]}"; do
    read -r _ iface _ _ _ _ _ <<<"$row"
    sudo ip link set "$iface" down 2>/dev/null || true
  done
  echo "VPS down."
}

case "${1:-}" in
  provision) provision ;;
  up)        up ;;
  encaps)    encaps ;;
  psk-apply) psk_apply ;;
  pubkeys)   pubkeys ;;
  down)      down ;;
  *) echo "usage: $0 {provision|up|encaps|psk-apply|pubkeys|down}"; exit 1 ;;
esac
