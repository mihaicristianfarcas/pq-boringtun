MAC_V_PRIV="iHlnjqCaY0gHjC/HnIzDO4gjOa60DF6tqbfxfFAUg0Y="
  PI_V_PUB="uEFI0rJ5kdJHP6GIWByeS/1UuDUK3/6yQukkOD8PVG0="
  MAC_P_PRIV="mDEUSkI9ILhmPJlOho9km9uBW8tFiBWuv/EFMDXn1HA="
  PI_P_PUB="dqmKREDw/ODvbrqDXBbwoQ3OJg4rBb+VKO6JhoNx7Sw="
  PI_IP="192.168.0.214"

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
