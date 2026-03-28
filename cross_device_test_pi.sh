  PI_V_PRIV="0Kd6ooJnQpg+mqSRw0P11R0EDb8vFrnFmDI7fFA0AG4="
  MAC_V_PUB="4S1XFyElH1748YEOCv1f0MDzqf8cy/lm4gC8GxCg4zU="
  PI_P_PRIV="ACO4M/dUlDdQaC0vuPCiT2NvhR2s4lSha/TR9q9NsGM="
  MAC_P_PUB="/29qKYJ4LoN3Wk3czw2DkwcaIbDnIDuq6d1RRfTqnG4="

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
