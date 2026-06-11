# Netns testbed for paper experiments #1 / #2 / #3

Linux network-namespace harness used by three experiments:

| Experiment | Script                | Question                                                          |
|------------|------------------------|-------------------------------------------------------------------|
| #1 MTU     | `mtu_sweep.sh`         | At what path MTU does the hybrid handshake start to fail, and how does an IP-fragment-dropping middlebox change that? |
| #2 RTT     | `rtt_loss_matrix.sh`   | How does the hybrid handshake-completion latency move with injected RTT and loss, and how does loss interact with the larger handshake packets? |
| #3 DoS     | `dos_flood.sh`         | How many handshakes/sec can a responder sustain under a flood, vanilla vs hybrid, and does MAC1 rejection short-circuit before the Encaps cost? |

All three reuse `lib.sh` for the topology and binary-build steps.

## Topology

```
+----------+   veth (path MTU = $PATH_MTU, optional tc netem)   +----------+
|  ns-init |==================================================== |  ns-resp |
+----------+ 10.99.0.1/24                          10.99.0.2/24 +----------+
   wg0=10.0.0.1/24      <-- userspace WireGuard -->     wg0=10.0.0.2/24
```

Boringtun runs as a regular userspace WG daemon in each namespace. The
underlay veth simulates the wide-area path; tc/iptables on the veth
toggle middlebox behaviour without changing the application code.

## Requirements

Linux 5.x+ with:
- `iproute2` (provides `ip`, `tc`)
- `iptables` (legacy or nft compat)
- `wireguard-tools` (provides `wg`, `wg-quick`)
- Rust toolchain (for building `boringtun-cli`)

Tested on the Raspberry Pi 5 running Raspberry Pi OS Bookworm (kernel 6.x)
and on Ubuntu 22.04 inside WSL2. WSL2's networking is real enough for the
netns scaffold to function, but RTT-injection results from WSL2 should be
read with a grain of salt — prefer the Pi for production paper numbers.

## Invocation

```bash
# All scripts must be run as root because of netns + iptables + tc.
sudo -E bash paper/testbeds/netns/mtu_sweep.sh
sudo -E bash paper/testbeds/netns/rtt_loss_matrix.sh
sudo -E bash paper/testbeds/netns/dos_flood.sh
```

Results land under `paper/measurements/netns-*.csv`. Each script tears
down its own netns state on exit; if it crashes mid-run, the next
invocation's `teardown_netns` is idempotent.

## Tuning knobs (env vars)

| Variable          | Default               | Effect                                   |
|-------------------|----------------------|------------------------------------------|
| `BIN_VANILLA`     | repo `target/release-vanilla/...` | Path to a pre-built vanilla `boringtun-cli`. |
| `BIN_PQ`          | repo `target/release-pq/...`      | Path to a pre-built `pq`-features binary.    |
| `TRIALS_PER_CELL` | varies per script    | Statistical sample size per matrix cell. |

If you've already built the binaries elsewhere, point `BIN_VANILLA` and
`BIN_PQ` at them and `build_binaries` becomes a no-op.

## Output schema

Each script emits a CSV header on the first line — the column meanings are
inlined at the top of the corresponding script. The R / Python notebook
that produces the paper figures lives outside this directory; for the
thesis-style LaTeX tables, the CSVs are pasted by hand.
