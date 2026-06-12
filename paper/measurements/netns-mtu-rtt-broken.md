# netns-mtu-sweep.csv and netns-rtt-loss-matrix.csv — broken testbed, do not cite

**Status:** the data in these two CSVs is not a measurement. Every cell shows
`successes=0, success_rate=0.00, rtt=NaN`, including the cells that should
trivially pass (`mtu=1500 drop_frags=none` for the MTU sweep, `delay_ms=0
loss_pct=0` for the RTT/loss matrix). A vanilla 148-byte handshake over a
clean veth pair has no reason to fail; the testbed is broken, not the
hybrid handshake.

The DoS-flood experiment (`netns-dos-flood.csv`) ran from the same `lib.sh`
scaffolding and produced clean CPU and packet-count numbers, so the basic
netns setup, dual-boringtun spin-up, and UDP transport are all working.
The bug is therefore localised to either `attempt_handshake` (the
ping-based handshake-success trial) or to the way `start_tunnels`
configures the wg0 device for the bidirectional handshake.

Until this is fixed, **the thesis does not cite the MTU sweep or the
RTT/loss matrix.** The relevant claims in chapter 9 (MTU management as
the most pressing operational concern, fragmentation strategies as future
work) remain prose-only, which is also what they were before this paper
branch existed.

## Likely root causes, ranked

1. **`attempt_handshake` uses ping, which depends on a handshake-completion
   side-effect we never verified directly.** The handshake might complete
   but the ICMP echo round-trip never makes it back, in which case the
   function returns `0,NaN` and we cannot distinguish handshake failure
   from a routing/ARP/MTU problem on `wg0`. First diagnostic step: add a
   `wg show wg0 latest-handshakes` check inside the function and report
   the latest-handshake timestamp instead of (or in addition to) ping
   success.

2. **The static `endpoint` is configured on both sides of the tunnel
   simultaneously.** Standard WireGuard usually sets endpoint only on the
   initiator; the responder learns it from the inbound packet. Setting it
   on both ends is not wrong, but it does interact with boringtun's
   default connected-UDP mode (each side `connect()`s its socket to the
   configured peer endpoint). It is possible that the responder's
   `connect()` happens before the initiator's first init arrives, so the
   reply leaves from a socket bound to a specific source port and the
   initiator's connected socket rejects it because of a mismatch. Worth
   trying: pass `--disable-connected-udp` to both daemons, or only set
   `endpoint` on the initiator.

3. **The `wg set` happens before `ip addr add` and `ip link set wg0 up`.**
   That order is fine on most boringtun versions, but if `wg set` is
   retried after the link is up the configuration may settle differently.
   Worth trying: bring the link up first, then `wg set`.

## Quick diagnostic recipe

```bash
sudo -E bash -c '
    source paper/testbeds/netns/lib.sh
    require_root
    require_deps
    build_binaries
    setup_netns 1500 ""
    read -r INIT_PID RESP_PID <<<"$(start_tunnels pq)"
    sleep 0.5
    echo "=== init netns wg show ==="
    ip netns exec pqwg-init wg show wg0
    echo "=== resp netns wg show ==="
    ip netns exec pqwg-resp wg show wg0
    echo "=== init -> resp ping ==="
    ip netns exec pqwg-init ping -c 3 -W 5 10.0.0.2
    echo "=== init boringtun log ==="
    cat /tmp/pqwg-pq-init.log
    echo "=== resp boringtun log ==="
    cat /tmp/pqwg-pq-resp.log
    stop_tunnels "$INIT_PID" "$RESP_PID"
    teardown_netns
'
```

The boringtun logs in `/tmp/pqwg-*-init.log` will say whether the daemon
came up cleanly, whether it saw the init, and whether the response was
sent. `wg show wg0` will report the last handshake timestamp if either
side completed it. The combination of those three signals is enough to
narrow the bug to one of the three causes above.

Once a cause is identified and a fix lands in `lib.sh`, re-run
`mtu_sweep.sh` and `rtt_loss_matrix.sh` and replace this file with the
real measurement notes.
