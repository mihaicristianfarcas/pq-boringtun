#!/usr/bin/env bash
#
# cross_device_test_pi.sh — Raspberry Pi side of the cross-device throughput
# test (see cross_device_test_mac.sh). Brings up the matching vanilla and
# PQ-hybrid tunnels and starts the iperf3 server.
#
# Key material is NOT hardcoded — nothing secret is committed. Generate keys
# per host and exchange public keys out of band (see cross_device_test_mac.sh),
# then export the values before running.
#
# Required env vars:  PI_V_PRIV  MAC_V_PUB  PI_P_PRIV  MAC_P_PUB
#
set -euo pipefail

PI_V_PRIV="${PI_V_PRIV:?export the Pi vanilla private key (wg genkey)}"
MAC_V_PUB="${MAC_V_PUB:?export the Mac vanilla public key}"
PI_P_PRIV="${PI_P_PRIV:?export the Pi PQ private key (wg genkey)}"
MAC_P_PUB="${MAC_P_PUB:?export the Mac PQ public key}"

# Vanilla tunnel (wg20, port 51860, 10.10.0.2)
sudo /tmp/boringtun-vanilla wg20 --disable-drop-privileges &
sleep 1
echo "$PI_V_PRIV" | sudo wg set wg20 private-key /dev/stdin listen-port 51860 \
    peer "$MAC_V_PUB" allowed-ips 10.10.0.1/32
sudo ip addr add 10.10.0.2/24 dev wg20
sudo ip link set wg20 up

# PQ Hybrid tunnel (wg21, port 51861, 10.10.1.2)
sudo /tmp/boringtun-pq wg21 --disable-drop-privileges &
sleep 1
echo "$PI_P_PRIV" | sudo wg set wg21 private-key /dev/stdin listen-port 51861 \
    peer "$MAC_P_PUB" allowed-ips 10.10.1.1/32
sudo ip addr add 10.10.1.2/24 dev wg21
sudo ip link set wg21 up

echo "Pi tunnels up. Starting iperf3 server..."
iperf3 -s -D --pidfile /tmp/iperf3-xdev.pid
echo "iperf3 server running."
