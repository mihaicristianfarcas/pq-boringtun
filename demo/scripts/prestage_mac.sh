#!/usr/bin/env bash
#
# prestage_mac.sh — one-command prep of the VPS demo from the Mac.
#
# Drives the VPS over SSH: syncs source, builds Linux binaries, brings up the
# three tunnels, runs the REAL cross-host ML-KEM-768 PSK exchange, then brings
# up the Mac side, forces a first handshake on each tunnel, and (on success)
# starts the web UI so everything is proven up and live before the talk.
#
# Required env (for bring-up; NOT for `down`):
#   DEMO_VPS_SSH    ssh target, e.g. ubuntu@203.0.113.9
#   DEMO_VPS_HOST   public IP/host the Mac points its endpoint at (often same)
# Optional:
#   DEMO_EGRESS_IFACE   physical iface (default en0)   DEMO_WORKDIR (default /tmp/pq-demo)
#   DEMO_AUTOSTART=0    prestage only; print the UI command instead of running it
#
# Run as your NORMAL user (so ssh/scp/rsync use YOUR keys). The local tunnel
# commands are individually elevated with sudo and will prompt once:
#   DEMO_VPS_SSH=ubuntu@1.2.3.4 DEMO_VPS_HOST=1.2.3.4 ./prestage_mac.sh
#
# Teardown (Mac always; VPS too if DEMO_VPS_SSH is set):
#   ./prestage_mac.sh down
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="${DEMO_WORKDIR:-/tmp/pq-demo}"
# NOT required up-front: `down` must work without them (otherwise a bare
# `prestage_mac.sh down` would abort here and silently leave the tunnels up).
VPS_SSH="${DEMO_VPS_SSH:-}"
VPS_HOST="${DEMO_VPS_HOST:-}"
VPS_SRC="/opt/pq-boringtun"
SUDO="${SUDO:-sudo}" # local tunnel commands need root; ssh/scp/rsync do NOT
mkdir -p "$WORKDIR"

# Atomic binary install — copy beside the target then rename over it, so a still
# running boringtun daemon never blocks the overwrite (Linux: "Text file busy").
install_bin() { cp "$1" "$2.new" && mv -f "$2.new" "$2"; }

if [ "$(id -u)" -eq 0 ]; then
	echo "Run as your normal user, NOT root — otherwise ssh/scp would use root's keys." >&2
	exit 1
fi

# name  iface  port   mac_ip       peer_ip      build    psk
ROWS=(
	"vanilla utun20 51820 10.13.0.1 10.13.0.2 vanilla no"
	"psk     utun21 51821 10.13.1.1 10.13.1.2 vanilla yes"
	"pq      utun22 51822 10.13.2.1 10.13.2.2 pq      no"
)
INTERFACES=(utun20 utun21 utun22)

remote() { ssh "$VPS_SSH" "PQ_SRC=$VPS_SRC DEMO_WORKDIR=$WORKDIR bash $VPS_SRC/demo/vps/setup.sh $*"; }

# --- teardown helpers --------------------------------------------------------
# Does the interface still exist?
iface_present() { ifconfig "$1" >/dev/null 2>&1; }

# Wait up to ~5s for an interface to disappear after its daemon dies — macOS
# frees the utun a beat *after* the owning process exits, so a flat `sleep 1`
# used to race and leave the next bring-up claiming an interface still in use.
wait_iface_gone() {
	local ifc="$1" i
	for i in $(seq 1 25); do
		iface_present "$ifc" || return 0
		sleep 0.2
	done
	iface_present "$ifc" && return 1 || return 0
}

# SIGTERM every boringtun daemon bound to our Mac interfaces. Daemons run as root
# (sudo), so the kill must be elevated. (cross_device_test_mac.sh also uses
# utun20/21, so clear by interface, not just our own pids.)
kill_iface_daemons() {
	for ifc in "${INTERFACES[@]}"; do
		$SUDO pkill -f "boringtun.* $ifc( |\$)" 2>/dev/null || true
	done
}

# Full Mac-side teardown: kill by recorded pid, then sweep by interface,
# escalating TERM -> KILL, and WAIT until each utun is actually released. Returns
# non-zero if any interface could not be cleared (so the caller can warn).
teardown_mac() {
	for f in "$WORKDIR"/*.mac.pid; do
		[ -e "$f" ] || continue
		$SUDO kill "$(cat "$f")" 2>/dev/null || true
		rm -f "$f"
	done
	kill_iface_daemons
	local rc=0 ifc
	for ifc in "${INTERFACES[@]}"; do
		if ! wait_iface_gone "$ifc"; then
			echo "  $ifc lingering after SIGTERM — sending SIGKILL…" >&2
			$SUDO pkill -9 -f "boringtun.* $ifc( |\$)" 2>/dev/null || true
			wait_iface_gone "$ifc" || {
				echo "  WARNING: could not clear $ifc (try: sudo pkill -9 -f $ifc)" >&2
				rc=1
			}
		fi
	done
	return $rc
}

# --- teardown: `prestage_mac.sh down` ----------------------------------------
if [ "${1:-}" = "down" ]; then
	echo "Tearing down demo tunnels…"
	if teardown_mac; then echo "  Mac tunnels cleared."; else echo "  Mac side: some interfaces could not be cleared (see above)."; fi
	if [ -n "$VPS_SSH" ]; then
		echo "Tearing down VPS tunnels ($VPS_SSH)…"
		ssh -o ConnectTimeout=8 "$VPS_SSH" "DEMO_WORKDIR=$WORKDIR bash $VPS_SRC/demo/vps/setup.sh down" 2>/dev/null ||
			echo "  (VPS unreachable or already down — skipped)"
	else
		echo "  DEMO_VPS_SSH not set — Mac side only. Set it to also tear down the VPS."
	fi
	echo "Done. (key material left in $WORKDIR; rm -rf it to fully reset)"
	exit 0
fi

# Past here we DO need the VPS coordinates.
: "${VPS_SSH:?set DEMO_VPS_SSH (e.g. ubuntu@1.2.3.4)}"
: "${VPS_HOST:?set DEMO_VPS_HOST (public IP the Mac dials)}"

# A prior `sudo local_fallback.sh` leaves WORKDIR root-owned; reclaim it so this
# user-run script can write keys/binaries there.
if [ ! -w "$WORKDIR" ]; then
	echo "Reclaiming $WORKDIR (root-owned from a prior sudo run)…"
	$SUDO chown -R "$(id -u):$(id -g)" "$WORKDIR"
fi

# Likewise, a prior `sudo` cargo build can leave files inside target/ root-owned,
# which breaks this user-run build (Permission denied writing .fingerprint).
if [ -d "$PROJECT_ROOT/target" ] && [ -n "$(find "$PROJECT_ROOT/target" -user root -print -quit 2>/dev/null)" ]; then
	echo "Reclaiming target/ (root-owned files from a prior sudo build)…"
	$SUDO chown -R "$(id -u):$(id -g)" "$PROJECT_ROOT/target"
fi

# On failure AFTER tunnels are started, don't leave half-up Mac daemons behind.
STARTED=0
cleanup_on_fail() {
	[ "$STARTED" = "1" ] || return 0
	echo >&2
	echo "prestage failed — cleaning up Mac tunnels (run with 'down' to also clear the VPS)…" >&2
	kill_iface_daemons
}
trap cleanup_on_fail ERR

echo "==> [1/7] Building Mac binaries"
cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml"
install_bin "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-vanilla"
cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" --features boringtun/pq
install_bin "$PROJECT_ROOT/target/debug/boringtun-cli" "$WORKDIR/boringtun-pq"
cargo build -p pq-psk-tool --manifest-path "$PROJECT_ROOT/Cargo.toml"
install_bin "$PROJECT_ROOT/target/debug/pq-psk-tool" "$WORKDIR/pq-psk-tool"

echo "==> [2/7] Syncing source to VPS and provisioning"
ssh "$VPS_SSH" "sudo mkdir -p $VPS_SRC && sudo chown \$(id -u):\$(id -g) $VPS_SRC"
rsync -az --delete --exclude thesis --exclude paper --exclude presentation --exclude target --exclude .git --exclude '.venv' --exclude '__pycache__' \
	"$PROJECT_ROOT/" "$VPS_SSH:$VPS_SRC/"
remote provision

echo "==> [3/7] Generating Mac keypairs"
declare -A MACPUB
for row in "${ROWS[@]}"; do
	read -r name iface port mip pip build psk <<<"$row"
	(
		umask 077
		wg genkey >"$WORKDIR/$name.mac.key"
	) # 0600 so wg doesn't warn
	MACPUB[$name]=$(wg pubkey <"$WORKDIR/$name.mac.key")
done

# Do the PSK exchange BEFORE bring-up so wgp is created WITH the preshared-key
# in a single `wg set` — boringtun rejects adding a PSK to an existing peer
# afterwards ("Unable to modify interface: Protocol error").
echo "==> [4/7] Cross-host ML-KEM-768 PSK exchange"
"$WORKDIR/pq-psk-tool" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
scp -q "$WORKDIR/mlkem_ek.b64" "$VPS_SSH:$WORKDIR/mlkem_ek.b64"
remote encaps
scp -q "$VPS_SSH:$WORKDIR/mlkem_ct.b64" "$WORKDIR/mlkem_ct.b64"
"$WORKDIR/pq-psk-tool" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.b64"

echo "==> [5/7] Bringing up VPS tunnels (wgp gets the PSK at creation)"
MAC_VANILLA_PUB="${MACPUB[vanilla]}" MAC_PSK_PUB="${MACPUB[psk]}" MAC_PQ_PUB="${MACPUB[pq]}" \
	ssh "$VPS_SSH" "PQ_SRC=$VPS_SRC DEMO_WORKDIR=$WORKDIR \
    MAC_VANILLA_PUB=${MACPUB[vanilla]} MAC_PSK_PUB=${MACPUB[psk]} MAC_PQ_PUB=${MACPUB[pq]} \
    bash $VPS_SRC/demo/vps/setup.sh up"
remote pubkeys >"$WORKDIR/vps_pubkeys"

echo "==> [6/7] Bringing up Mac tunnels"
STARTED=1
# Clear any leftover demo daemons and WAIT for their utun numbers to be released
# before we try to claim them (this is what prevents "utun22 already in use").
teardown_mac || echo "  (continuing despite a stuck interface — bring-up may fail on it)" >&2
for row in "${ROWS[@]}"; do
	read -r name iface port mip pip build psk <<<"$row"
	bin="$WORKDIR/boringtun-$build"
	vpspub=$(awk -v n="$name" '$1==n{print $2}' "$WORKDIR/vps_pubkeys")
	echo "$vpspub" >"$WORKDIR/$name.peerpub" # orchestrator uses this to re-handshake

	# --foreground logs to STDOUT, so redirect BOTH streams into the log file —
	# that keeps the terminal clean regardless of level. debug so the UI's live
	# handshake-log strip has events to tail (it parses the per-tunnel .mac.log);
	# set WG_LOG_LEVEL=info to quiet the files if you don't need the strip.
	$SUDO env WG_LOG_LEVEL="${WG_LOG_LEVEL:-debug}" "$bin" "$iface" --foreground --disable-drop-privileges >"$WORKDIR/$name.mac.log" 2>&1 &
	mpid=$!
	echo "$mpid" >"$WORKDIR/$name.mac.pid"
	sleep 1
	if ! kill -0 "$mpid" 2>/dev/null; then
		echo "ERROR: $name daemon for $iface exited on start." >&2
		echo "  --- last lines of $WORKDIR/$name.mac.log ---" >&2
		tail -n 8 "$WORKDIR/$name.mac.log" 2>/dev/null | sed 's/^/  /' >&2 || true
		if iface_present "$iface"; then
			echo "  $iface still exists — another process is holding it:" >&2
			$SUDO pgrep -fl "$iface" 2>/dev/null | sed 's/^/  /' >&2 || true
			echo "  clear it with '$0 down' (or: sudo pkill -9 -f $iface), then retry." >&2
		fi
		exit 1
	fi

	psk_args=()
	[ "$psk" = "yes" ] && psk_args=(preshared-key "$WORKDIR/psk.b64")
	$SUDO wg set "$iface" private-key "$WORKDIR/$name.mac.key" listen-port "$port" \
		peer "$vpspub" "${psk_args[@]}" endpoint "$VPS_HOST:$port" allowed-ips "$pip/32"
	$SUDO ifconfig "$iface" "$mip" "$pip"
	echo "  $name: $iface=$mip -> $VPS_HOST:$port (peer $pip)"
done

echo "==> [7/7] Forcing first handshakes"
# Two packets with a generous budget: the FIRST has to trigger the handshake and
# ride a slow real-network RTT, so a single -c 1 -t 2 probe times out marginally
# (it was the PSK tunnel that lost the race, not a broken PSK). -c 2 -t 5 passes
# if EITHER reply comes back — the handshake itself always completes here.
all_ok=1
for row in "${ROWS[@]}"; do
	read -r name _ _ _ pip _ _ <<<"$row"
	if ping -c 2 -t 5 "$pip" >/dev/null 2>&1; then
		echo "  $name: handshake OK ($pip)"
	else
		echo "  $name: ping failed — see $WORKDIR/$name.mac.log"
		all_ok=0
	fi
done

# --- start the UI (issue: prestage should leave a running demo, not homework) -
UI_CMD="cd demo/backend && uv run python app.py --vps-host $VPS_HOST --egress-iface ${DEMO_EGRESS_IFACE:-en0}"
echo
if [ "$all_ok" = "1" ] && [ "${DEMO_AUTOSTART:-1}" != "0" ] && command -v uv >/dev/null 2>&1; then
	echo "All three tunnels are up. Starting the UI on http://127.0.0.1:8000 …"
	echo "  (Ctrl-C stops the UI only — the tunnels stay up. Run '$0 down' to remove them.)"
	echo
	# The UI's lifetime is the user's now; its exit must NOT trip the ERR/cleanup
	# trap and tear the tunnels down. Hand the terminal straight to uvicorn.
	trap - ERR
	cd "$PROJECT_ROOT/demo/backend"
	exec uv run python app.py --vps-host "$VPS_HOST" --egress-iface "${DEMO_EGRESS_IFACE:-en0}"
fi

if [ "$all_ok" != "1" ]; then
	echo "Some tunnels failed their first handshake — NOT auto-starting the UI."
	echo "Check the logs above, then start it yourself once they're healthy:"
elif ! command -v uv >/dev/null 2>&1; then
	echo "Prestaged, but 'uv' is not on PATH — start the UI yourself:"
else
	echo "Prestaged (auto-start disabled via DEMO_AUTOSTART=0). Start the UI:"
fi
echo "  $UI_CMD"
