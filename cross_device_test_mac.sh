#!/usr/bin/env bash
#
# cross_device_test_mac.sh — Mac side of the cross-device throughput test
# (Mac <-> Raspberry Pi over the LAN), used for the Chapter 8 throughput numbers.
#
# Brings up two parallel tunnels: a vanilla one and a PQ-hybrid one.
#
# Key material is NOT hardcoded. Generate it once per host and exchange public
# keys out of band, then export the values before running. Private keys stay on
# their own host:
#
#   On the Mac:  MAC_V_PRIV=$(wg genkey); echo "$MAC_V_PRIV" | wg pubkey   # -> give MAC_V_PUB to the Pi
#                MAC_P_PRIV=$(wg genkey); echo "$MAC_P_PRIV" | wg pubkey   # -> give MAC_P_PUB to the Pi
#   On the Pi:   (likewise) -> gives you PI_V_PUB and PI_P_PUB
#
# Required env vars:  MAC_V_PRIV  PI_V_PUB  MAC_P_PRIV  PI_P_PUB  PI_IP
#
set -euo pipefail

MAC_V_PRIV="${MAC_V_PRIV:?export the Mac vanilla private key (wg genkey)}"
PI_V_PUB="${PI_V_PUB:?export the Pi vanilla public key}"
MAC_P_PRIV="${MAC_P_PRIV:?export the Mac PQ private key (wg genkey)}"
PI_P_PUB="${PI_P_PUB:?export the Pi PQ public key}"
PI_IP="${PI_IP:?export the Pi LAN IP address}"

# Vanilla tunnel (utun20, port 51860, 10.10.0.1)
sudo /tmp/boringtun-vanilla utun20 --disable-drop-privileges &
sleep 1
echo "$MAC_V_PRIV" | sudo wg set utun20 private-key /dev/stdin listen-port 51860 \
    peer "$PI_V_PUB" endpoint "$PI_IP":51860 allowed-ips 10.10.0.2/32
sudo ifconfig utun20 10.10.0.1 10.10.0.2

# PQ Hybrid tunnel (utun21, port 51861, 10.10.1.1)
sudo /tmp/boringtun-pq utun21 --disable-drop-privileges &
sleep 1
echo "$MAC_P_PRIV" | sudo wg set utun21 private-key /dev/stdin listen-port 51861 \
    peer "$PI_P_PUB" endpoint "$PI_IP":51861 allowed-ips 10.10.1.2/32
sudo ifconfig utun21 10.10.1.1 10.10.1.2

echo "Mac tunnels up. With the Pi running its iperf3 server, measure with:"
echo "  iperf3 -c 10.10.0.2 -t 15   # vanilla"
echo "  iperf3 -c 10.10.1.2 -t 15   # PQ hybrid"
