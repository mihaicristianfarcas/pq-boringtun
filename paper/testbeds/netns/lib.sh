#!/usr/bin/env bash
#
# Common scaffolding for the netns testbeds.
#
# Topology (after `setup_netns`):
#
#   +----------+     veth pair (path-MTU $PATH_MTU)     +----------+
#   |  ns-init |=========================================|  ns-resp |
#   +----------+ 10.99.0.1/24                10.99.0.2/24 +----------+
#       |                                                       |
#   wg0=10.0.0.1/24      <-- boringtun userspace WG -->      wg0=10.0.0.2/24
#
# Inside each ns, boringtun runs as a userspace WireGuard daemon. The two
# tunnels handshake over the veth link. Path MTU, IP-fragment drops, and tc
# netem delay/loss can be toggled on the veth devices to model real-world
# transport pathologies without leaving the host.
#
# Source this file from per-experiment scripts:
#
#   source "$(dirname "$0")/lib.sh"
#   require_root
#   build_binaries
#   setup_netns 1280 drop_frags     # MTU, optional fragment-drop flag
#   run_handshake_trial pq          # 'vanilla' or 'pq'
#   teardown_netns
#
# All functions are idempotent: re-running setup after a crashed previous run
# tears down stale state first.

set -euo pipefail

# ----- Constants ------------------------------------------------------------

NS_INIT="pqwg-init"
NS_RESP="pqwg-resp"
VETH_INIT="vinit"
VETH_RESP="vresp"

UNDERLAY_INIT_IP="10.99.0.1"
UNDERLAY_RESP_IP="10.99.0.2"
UNDERLAY_CIDR="24"

WG_INIT_IP="10.0.0.1"
WG_RESP_IP="10.0.0.2"
WG_CIDR="24"

INIT_PORT="51820"
RESP_PORT="51821"

# Paths (overridable from caller).
#
# With `CARGO_TARGET_DIR=$dir cargo build --release`, the binary lands at
# $dir/release/boringtun-cli — the per-mode CARGO_TARGET_DIR adds one
# directory level above cargo's own `release/` subdir.
: "${REPO_ROOT:=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
: "${BIN_VANILLA:=$REPO_ROOT/target/release-vanilla/release/boringtun-cli}"
: "${BIN_PQ:=$REPO_ROOT/target/release-pq/release/boringtun-cli}"

# ----- Helpers --------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "must run as root (try: sudo -E $0 ...)"
}

# Sudo (with or without -E) strips `secure_path` over the inherited PATH, so
# rustup's ~/.cargo/bin disappears for the script's child processes. Recover
# it from the invoking user's home before the dep check runs.
ensure_user_cargo_on_path() {
    command -v cargo >/dev/null 2>&1 && return 0
    local user_home=""
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    [[ -z "$user_home" ]] && user_home="$HOME"
    if [[ -x "$user_home/.cargo/bin/cargo" ]]; then
        export PATH="$user_home/.cargo/bin:$PATH"
    fi
}

# Bail early with a clear message if a hard dependency is missing.
require_deps() {
    ensure_user_cargo_on_path
    local missing=()
    for cmd in ip wg iptables tc ping cargo; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        die "missing required commands: ${missing[*]} (apt install wireguard-tools iproute2 iptables iputils-ping; install rustup for cargo)"
    fi
}

# Build both feature modes into per-feature target directories so we don't
# thrash rebuilds when switching modes. Only rebuilds if the binary is stale.
build_binaries() {
    log "building boringtun-cli (vanilla + pq)"
    (
        cd "$REPO_ROOT"
        CARGO_TARGET_DIR="$REPO_ROOT/target/release-vanilla" \
            cargo build --release -p boringtun-cli >/dev/null
        CARGO_TARGET_DIR="$REPO_ROOT/target/release-pq" \
            cargo build --release -p boringtun-cli --features boringtun/pq >/dev/null
    )
    [[ -x "$BIN_VANILLA" ]] || die "vanilla binary not at $BIN_VANILLA"
    [[ -x "$BIN_PQ"      ]] || die "pq binary not at $BIN_PQ"
}

# Generate a fresh keypair (private + derived public). Echoes "PRIV PUB".
genkey_pair() {
    local priv pub
    priv=$(wg genkey)
    pub=$(echo "$priv" | wg pubkey)
    echo "$priv $pub"
}

# ----- Netns lifecycle ------------------------------------------------------

teardown_netns() {
    log "tearing down netns"
    ip netns del "$NS_INIT" 2>/dev/null || true
    ip netns del "$NS_RESP" 2>/dev/null || true
    # Veth devices are auto-removed with the netns; if either remained in the
    # default ns (because setup half-finished), drop them explicitly.
    ip link del "$VETH_INIT" 2>/dev/null || true
    ip link del "$VETH_RESP" 2>/dev/null || true
}

# setup_netns <path_mtu> [drop_frags]
#
#   path_mtu     — MTU set on both veth ends (1500 = uncapped Ethernet).
#   drop_frags   — pass the literal string 'drop_frags' to add an iptables
#                  rule on the responder side dropping IPv4 fragments
#                  (simulates middlebox that does not handle fragments).
setup_netns() {
    local path_mtu="$1"
    local drop_frags="${2:-}"

    teardown_netns  # idempotent

    log "setting up netns (path_mtu=$path_mtu drop_frags=${drop_frags:-no})"

    ip netns add "$NS_INIT"
    ip netns add "$NS_RESP"

    ip link add "$VETH_INIT" type veth peer name "$VETH_RESP"
    ip link set "$VETH_INIT" netns "$NS_INIT"
    ip link set "$VETH_RESP" netns "$NS_RESP"

    ip -n "$NS_INIT" addr add "$UNDERLAY_INIT_IP/$UNDERLAY_CIDR" dev "$VETH_INIT"
    ip -n "$NS_RESP" addr add "$UNDERLAY_RESP_IP/$UNDERLAY_CIDR" dev "$VETH_RESP"

    ip -n "$NS_INIT" link set "$VETH_INIT" mtu "$path_mtu" up
    ip -n "$NS_RESP" link set "$VETH_RESP" mtu "$path_mtu" up
    ip -n "$NS_INIT" link set lo up
    ip -n "$NS_RESP" link set lo up

    if [[ "$drop_frags" == "drop_frags" ]]; then
        # Drop all non-first IPv4 fragments inbound on the responder.
        # The kernel matches `-f` against "second and further fragments".
        ip netns exec "$NS_RESP" iptables -I INPUT -i "$VETH_RESP" -f -j DROP
        # And on the init side, drop fragments going back the other way too,
        # so the path is symmetric.
        ip netns exec "$NS_INIT" iptables -I INPUT -i "$VETH_INIT" -f -j DROP
    fi
}

# add_netem <ns> <iface> <delay_ms> <loss_pct>
#
# Attach a netem qdisc to the given interface (egress shaping). Cumulative if
# called more than once — call clear_netem first if you want to reset.
add_netem() {
    local ns="$1" iface="$2" delay_ms="$3" loss_pct="$4"
    ip netns exec "$ns" tc qdisc add dev "$iface" root netem \
        delay "${delay_ms}ms" loss "${loss_pct}%"
}

clear_netem() {
    local ns="$1" iface="$2"
    ip netns exec "$ns" tc qdisc del dev "$iface" root 2>/dev/null || true
}

# ----- WireGuard wiring ----------------------------------------------------

# Starts both boringtun daemons (one per netns), provisions wg config, brings
# up the tunnels. Echoes the PIDs of the two daemons (init resp) so the
# caller can record / kill them.
#
# Usage: start_tunnels <mode>    where mode ∈ {vanilla, pq}
#
# Writes per-daemon logs to /tmp/pqwg-<mode>-{init,resp}.log.
start_tunnels() {
    local mode="$1"
    local bin
    case "$mode" in
        vanilla) bin="$BIN_VANILLA" ;;
        pq)      bin="$BIN_PQ" ;;
        *) die "unknown mode '$mode' (expected vanilla|pq)" ;;
    esac
    [[ -x "$bin" ]] || die "binary not found: $bin"

    log "starting tunnels (mode=$mode)"

    # Fresh keys per run keep us honest about cold-state handshake cost.
    read -r INIT_PRIV INIT_PUB <<<"$(genkey_pair)"
    read -r RESP_PRIV RESP_PUB <<<"$(genkey_pair)"

    # Boringtun in foreground mode logs to stderr; redirect per-daemon.
    ip netns exec "$NS_INIT" \
        "$bin" wg0 --foreground --disable-drop-privileges \
        >/tmp/pqwg-"$mode"-init.log 2>&1 &
    INIT_PID=$!

    ip netns exec "$NS_RESP" \
        "$bin" wg0 --foreground --disable-drop-privileges \
        >/tmp/pqwg-"$mode"-resp.log 2>&1 &
    RESP_PID=$!

    # Wait for the wg0 device to appear in each ns.
    for ns in "$NS_INIT" "$NS_RESP"; do
        for i in {1..50}; do
            ip netns exec "$ns" ip link show wg0 >/dev/null 2>&1 && break
            sleep 0.1
        done
    done

    # Configure both ends. Responder listens on $RESP_PORT.
    echo "$INIT_PRIV" | ip netns exec "$NS_INIT" wg set wg0 \
        private-key /dev/stdin listen-port "$INIT_PORT" \
        peer "$RESP_PUB" allowed-ips "$WG_RESP_IP/32" \
        endpoint "$UNDERLAY_RESP_IP:$RESP_PORT" \
        persistent-keepalive 0

    echo "$RESP_PRIV" | ip netns exec "$NS_RESP" wg set wg0 \
        private-key /dev/stdin listen-port "$RESP_PORT" \
        peer "$INIT_PUB" allowed-ips "$WG_INIT_IP/32" \
        endpoint "$UNDERLAY_INIT_IP:$INIT_PORT" \
        persistent-keepalive 0

    ip -n "$NS_INIT" addr add "$WG_INIT_IP/$WG_CIDR" dev wg0
    ip -n "$NS_RESP" addr add "$WG_RESP_IP/$WG_CIDR" dev wg0
    ip -n "$NS_INIT" link set wg0 up
    ip -n "$NS_RESP" link set wg0 up

    echo "$INIT_PID $RESP_PID"
}

stop_tunnels() {
    log "stopping tunnels"
    for pid in "$@"; do
        # `ip netns exec` may fork once before exec, leaving the boringtun
        # daemon as a child of the backgrounded shell wrapper. Kill any
        # remaining children before SIGTERM'ing the wrapper itself, so we
        # don't orphan a daemon that keeps wg0 open for the next cell.
        pkill -TERM -P "$pid" 2>/dev/null || true
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "$@"; do
        pkill -KILL -P "$pid" 2>/dev/null || true
        kill -KILL "$pid" 2>/dev/null || true
    done
}

# Attempt a single handshake by pinging from init to resp through the tunnel,
# with a 5 s timeout. Echoes one CSV row:
#
#   success,rtt_ms
#
# where success ∈ {0,1} and rtt_ms is the first-ping round-trip time (which
# includes the handshake cost). On failure, rtt_ms is NaN.
attempt_handshake() {
    local out rc rtt
    out=$(ip netns exec "$NS_INIT" ping -c 1 -W 5 "$WG_RESP_IP" 2>&1 || true)
    rc=$?
    if echo "$out" | grep -q "1 received"; then
        rtt=$(echo "$out" | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p')
        echo "1,${rtt:-NaN}"
    else
        echo "0,NaN"
    fi
}
