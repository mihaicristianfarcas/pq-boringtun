#!/usr/bin/env bash
#
# local_fallback.sh — bring up all three demo tunnels on THIS Mac over loopback.
#
# This is the bullet-proof fallback for an unstable defense-room network, and
# the only path you can rehearse without a VPS. Each variant is a pair of
# boringtun interfaces on localhost (mirrors `pq-hybrid-test.sh compare`).
#
#   sudo ./local_fallback.sh up      # build, start tunnels + receiver + UI
#   sudo ./local_fallback.sh down    # tear everything down
#
# The backend is auto-started at the end of `up` (requires uv on PATH).
# Set DEMO_AUTOSTART=0 to skip it and print the command instead.
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

INTERFACES=(utun20 utun21 utun22 utun30 utun31 utun32)

require_root() {
  if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 1; fi
}

# Kill ANY boringtun bound to our demo interfaces — including stale daemons from
# a previous run that the pid-file teardown can't see. macOS frees the utun once
# its owning process dies, so this also clears the interface numbers for reuse.
kill_iface_daemons() {
  for ifc in "${INTERFACES[@]}"; do
    pkill -f "boringtun.* $ifc( |\$)" 2>/dev/null || true
  done
}

# Does the interface still exist?
iface_present() { ifconfig "$1" >/dev/null 2>&1; }

# Wait up to ~5s for an interface to disappear after its daemon dies — macOS
# frees the utun a beat *after* the owning process exits, so a flat `sleep 1`
# raced and the next bring-up claimed an interface still in use.
wait_iface_gone() {
  local ifc="$1" i
  for i in $(seq 1 25); do
    iface_present "$ifc" || return 0
    sleep 0.2
  done
  iface_present "$ifc" && return 1 || return 0
}

# Robust teardown: SIGTERM leftover daemons by interface, then WAIT until each
# utun is actually released, escalating to SIGKILL for stragglers.
clear_ifaces() {
  kill_iface_daemons
  local ifc
  for ifc in "${INTERFACES[@]}"; do
    if ! wait_iface_gone "$ifc"; then
      pkill -9 -f "boringtun.* $ifc( |\$)" 2>/dev/null || true
      wait_iface_gone "$ifc" || echo "  WARNING: could not clear $ifc (try: sudo pkill -9 -f $ifc)" >&2
    fi
  done
}

# Verify a just-started daemon actually claimed its interface — a silent exit
# means the utun number was taken (exactly how the PSK tunnel once broke). On
# failure, show the log tail + whoever is holding the interface, then bail.
check_daemon() {  # label iface pid logfile
  local label="$1" ifc="$2" pid="$3" log="$4"
  kill -0 "$pid" 2>/dev/null && return 0
  echo "ERROR: $label daemon for $ifc exited on start." >&2
  echo "  --- last lines of $log ---" >&2
  tail -n 8 "$log" 2>/dev/null | sed 's/^/  /' >&2 || true
  if iface_present "$ifc"; then
    echo "  $ifc still exists — another process is holding it:" >&2
    pgrep -fl "$ifc" 2>/dev/null | sed 's/^/  /' >&2 || true
    echo "  clear it with '$0 down' (or: sudo pkill -9 -f $ifc), then retry." >&2
  fi
  exit 1
}

# Atomic binary install — rename over the target instead of overwriting in place,
# so a surviving daemon never trips "Text file busy" on the rebuild.
install_bin() { cp "$1" "$2.new" && mv -f "$2.new" "$2"; }

build_binaries() {
  echo "--- Building boringtun (vanilla + pq) and pq-psk-tool ---"
  cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml"
  install_bin "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-vanilla"
  cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" --features boringtun/pq
  install_bin "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-pq"
  cargo build -p pq-psk-tool --manifest-path "$PROJECT_ROOT/Cargo.toml"
  install_bin "$PROJECT_ROOT/target/debug/pq-psk-tool" "$WORKDIR/pq-psk-tool"
  # This script runs as root, so cargo just root-owned target/. Hand it back to
  # the invoking user so a later user-run build (e.g. prestage) still works.
  [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$PROJECT_ROOT/target" 2>/dev/null || true
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
  echo "--- Clearing any stale boringtun on $WORKDIR interfaces ---"
  clear_ifaces   # kill leftovers AND wait until each utun is released
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

    # daemons (check_daemon verifies each actually claimed its interface — a
    # silent exit means the utun number was taken). --foreground logs to STDOUT:
    # redirect BOTH streams so the trace lands in the log file, not the terminal.
    # debug so the UI live-log strip has events to tail; set WG_LOG_LEVEL=info to
    # quiet the files if you don't need the strip.
    WG_LOG_LEVEL="${WG_LOG_LEVEL:-debug}" "$bin" "$mif" --foreground --disable-drop-privileges >"$WORKDIR/$name.mac.log" 2>&1 &
    mpid=$!; echo "$mpid" >"$WORKDIR/$name.mac.pid"; sleep 1
    check_daemon "$name(mac)" "$mif" "$mpid" "$WORKDIR/$name.mac.log"
    WG_LOG_LEVEL="${WG_LOG_LEVEL:-debug}" "$bin" "$pif" --foreground --disable-drop-privileges >"$WORKDIR/$name.peer.log" 2>&1 &
    ppid=$!; echo "$ppid" >"$WORKDIR/$name.peer.pid"; sleep 1
    check_daemon "$name(peer)" "$pif" "$ppid" "$WORKDIR/$name.peer.log"

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
  pkill -f "receiver.py" 2>/dev/null || true  # drop a stale receiver holding the port
  python3 "$PROJECT_ROOT/demo/vps/receiver.py" --port "$RECEIVER_PORT" \
      >"$WORKDIR/receiver.log" 2>&1 &
  echo $! >"$WORKDIR/receiver.pid"

  echo "--- Forcing first handshakes ---"
  local all_ok=1
  for row in "${ROWS[@]}"; do
    read -r name _ _ _ _ _ pip _ _ <<<"$row"
    # -c 2 -t 5: first packet triggers the handshake, second confirms reachability
    if ping -c 2 -t 5 "$pip" >/dev/null 2>&1; then
      echo "  $name: handshake OK ($pip)"
    else
      echo "  $name: ping failed (check $WORKDIR/$name.mac.log)"
      all_ok=0
    fi
  done

  # --- start the UI (mirrors prestage_mac.sh) -----------------------------------
  UI_CMD="cd demo/backend && uv run python app.py --local"
  echo
  if [ "$all_ok" = "1" ] && [ "${DEMO_AUTOSTART:-1}" != "0" ] && command -v uv >/dev/null 2>&1; then
    echo "All three tunnels are up. Starting the UI on http://127.0.0.1:8000 …"
    echo "  (Ctrl-C stops the UI only — tunnels stay up. Run '$0 down' to remove them.)"
    echo
    # Hand the terminal to uvicorn; its exit must NOT trip the ERR trap.
    trap - ERR 2>/dev/null || true
    cd "$PROJECT_ROOT/demo/backend"
    exec uv run python app.py --local
  fi

  if [ "$all_ok" != "1" ]; then
    echo "Some tunnels failed their first handshake — NOT auto-starting the UI."
    echo "Check the logs above, then start it yourself once they're healthy:"
  elif ! command -v uv >/dev/null 2>&1; then
    echo "Local fallback up, but 'uv' is not on PATH — start the UI yourself:"
  else
    echo "Local fallback up (auto-start disabled via DEMO_AUTOSTART=0). Start the UI:"
  fi
  echo "  $UI_CMD"
}

down() {
  require_root
  echo "--- Tearing down ---"
  pkill -f "receiver.py" 2>/dev/null || true
  for f in "$WORKDIR"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  done
  # also clear any stale daemons not tracked by a pid file, and WAIT for macOS to
  # release each utun so an immediate re-`up` doesn't hit "interface in use".
  clear_ifaces
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
