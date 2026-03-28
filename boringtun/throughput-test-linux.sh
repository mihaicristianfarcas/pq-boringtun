#!/usr/bin/env bash
# throughput-test-linux.sh — loopback throughput test for Linux (Raspberry Pi)
# Must be run as root (sudo).
set -euo pipefail

VANILLA_BIN="${1:-/tmp/boringtun-vanilla}"
PQ_BIN="${2:-/tmp/boringtun-pq}"
WORKDIR="/tmp/bt-throughput-test"
mkdir -p "$WORKDIR"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo."
    exit 1
fi

cleanup() {
    kill "$PID_VA" "$PID_VB" "$PID_PA" "$PID_PB" 2>/dev/null || true
    wait 2>/dev/null || true
    ip link del wg10 2>/dev/null || true
    ip link del wg11 2>/dev/null || true
    ip link del wg12 2>/dev/null || true
    ip link del wg13 2>/dev/null || true
    kill "$(cat /tmp/iperf3-bt.pid 2>/dev/null)" 2>/dev/null || true
    rm -f "$WORKDIR"/*.key /tmp/iperf3-bt.pid
}
trap cleanup EXIT

# --- Vanilla tunnel (wg10/wg11, ports 51840/51841, 10.0.3.x) ---
echo "--- Setting up VANILLA tunnel ---"
V_A_PRIV=$(wg genkey); V_A_PUB=$(echo "$V_A_PRIV" | wg pubkey)
V_B_PRIV=$(wg genkey); V_B_PUB=$(echo "$V_B_PRIV" | wg pubkey)
echo "$V_A_PRIV" > "$WORKDIR/va.key"
echo "$V_B_PRIV" > "$WORKDIR/vb.key"

WG_LOG_LEVEL=error "$VANILLA_BIN" wg10 --disable-drop-privileges 2>/dev/null &
PID_VA=$!; sleep 1
WG_LOG_LEVEL=error "$VANILLA_BIN" wg11 --disable-drop-privileges 2>/dev/null &
PID_VB=$!; sleep 1

wg set wg10 private-key "$WORKDIR/va.key" listen-port 51840 \
    peer "$V_B_PUB" endpoint 127.0.0.1:51841 allowed-ips 10.0.3.2/32
wg set wg11 private-key "$WORKDIR/vb.key" listen-port 51841 \
    peer "$V_A_PUB" endpoint 127.0.0.1:51840 allowed-ips 10.0.3.1/32
ip addr add 10.0.3.1/24 dev wg10; ip link set wg10 up
ip addr add 10.0.3.2/24 dev wg11; ip link set wg11 up

# Trigger handshake
ping -c 1 -W 2 10.0.3.2 > /dev/null && echo "Vanilla tunnel: OK" || echo "Vanilla tunnel: FAILED"

# --- PQ Hybrid tunnel (wg12/wg13, ports 51842/51843, 10.0.4.x) ---
echo "--- Setting up PQ HYBRID tunnel ---"
P_A_PRIV=$(wg genkey); P_A_PUB=$(echo "$P_A_PRIV" | wg pubkey)
P_B_PRIV=$(wg genkey); P_B_PUB=$(echo "$P_B_PRIV" | wg pubkey)
echo "$P_A_PRIV" > "$WORKDIR/pa.key"
echo "$P_B_PRIV" > "$WORKDIR/pb.key"

WG_LOG_LEVEL=error "$PQ_BIN" wg12 --disable-drop-privileges 2>/dev/null &
PID_PA=$!; sleep 1
WG_LOG_LEVEL=error "$PQ_BIN" wg13 --disable-drop-privileges 2>/dev/null &
PID_PB=$!; sleep 1

wg set wg12 private-key "$WORKDIR/pa.key" listen-port 51842 \
    peer "$P_B_PUB" endpoint 127.0.0.1:51843 allowed-ips 10.0.4.2/32
wg set wg13 private-key "$WORKDIR/pb.key" listen-port 51843 \
    peer "$P_A_PUB" endpoint 127.0.0.1:51842 allowed-ips 10.0.4.1/32
ip addr add 10.0.4.1/24 dev wg12; ip link set wg12 up
ip addr add 10.0.4.2/24 dev wg13; ip link set wg13 up

ping -c 1 -W 2 10.0.4.2 > /dev/null && echo "PQ Hybrid tunnel: OK" || echo "PQ Hybrid tunnel: FAILED"

# --- Throughput ---
echo ""
echo "--- Running iperf3 throughput tests (15s each) ---"
iperf3 -s -D --pidfile /tmp/iperf3-bt.pid
sleep 1

echo -n "Vanilla  (10.0.3.2): "
iperf3 -c 10.0.3.2 -t 15 -i 0 2>&1 | grep -E "receiver|sender" | tail -1

echo -n "PQ Hybrid (10.0.4.2): "
iperf3 -c 10.0.4.2 -t 15 -i 0 2>&1 | grep -E "receiver|sender" | tail -1

echo ""
echo "Done. Cleaning up."
