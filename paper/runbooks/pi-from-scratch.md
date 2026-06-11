# Raspberry Pi 5 measurement runbook (from-scratch checkout)

Reproduces every paper-relevant measurement on the Pi: the existing
Criterion benches (with the new ML-KEM-512/1024 cells), the memory probe,
and the three netns testbeds (#1 MTU, #2 RTT/loss, #3 DoS).

Assumes a clean Pi 5 running Raspberry Pi OS Bookworm (kernel 6.x) with
no prior tooling installed.

## 0. Toolchain + dependencies (one-time)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config git curl \
    wireguard-tools iproute2 iptables iperf3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup default stable
rustc -vV | grep host   # expect: host: aarch64-unknown-linux-gnu
```

## 1. Clone the paper branch

```bash
cd ~
git clone https://github.com/<you>/pq-boringtun.git
cd pq-boringtun
git checkout paper
```

## 2. Cargo runner override

The repo's `.cargo/config.toml` pins `runner = 'sudo -E'` for cfg(unix)
so that macOS tests can open a TUN device. On the Pi we run benches and
examples that need no elevation. Override locally:

```bash
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="env"
```

(The netns testbeds need root anyway and invoke it themselves via `sudo`
on the script entry, so the runner override does not interfere with them.)

## 3. Criterion bench: ML-KEM parameter sweep + everything else

```bash
# Vanilla (no ML-KEM)
cargo bench --bench crypto_benches \
    2>&1 | tee paper/measurements/pi-crypto-vanilla.txt

# Hybrid (adds ML-KEM-512/768/1024 to the bench group)
cargo bench --bench crypto_benches --features pq \
    2>&1 | tee paper/measurements/pi-crypto-pq.txt
```

```bash
# Handshake bench (vanilla + psk_slot order-randomised)
cargo bench --bench handshake_benches \
    2>&1 | tee paper/measurements/pi-handshake-vanilla.txt
# Handshake bench (hybrid only)
cargo bench --bench handshake_benches --features pq \
    2>&1 | tee paper/measurements/pi-handshake-pq.txt
```

Expect ≈ 4 min per Criterion pass.

Compact-summary extraction (one line per benchmark):

```bash
grep -E "^[a-z0-9_/]+ +time:" paper/measurements/pi-crypto-{vanilla,pq}.txt
grep -E "^[a-z0-9_/]+ +time:" paper/measurements/pi-handshake-{vanilla,pq}.txt
```

Paste those compact lines into the thesis tables (or the corresponding
files under `paper/measurements/`).

## 4. Memory probe

```bash
cargo run --release --example memory_probe \
    2>&1 | tee paper/measurements/pi-memory-vanilla.txt
cargo run --release --example memory_probe --features pq \
    2>&1 | tee paper/measurements/pi-memory-pq.txt
```

Each emits `sizeof_Tunn`, `sizeof_Handshake`, and a 3-row CSV. Paste both
into `paper/measurements/memory-footprint.md` under the "Pi 5" section.

## 5. Netns testbeds (require root)

Each script is self-contained. Run sequentially:

```bash
sudo -E bash paper/testbeds/netns/mtu_sweep.sh
sudo -E bash paper/testbeds/netns/rtt_loss_matrix.sh
sudo -E bash paper/testbeds/netns/dos_flood.sh
```

Approximate runtimes on Pi 5:
- `mtu_sweep.sh`        ≈ 12 min
- `rtt_loss_matrix.sh`  ≈ 25 min
- `dos_flood.sh`        ≈   2 min

Results land in:

- `paper/measurements/netns-mtu-sweep.csv`
- `paper/measurements/netns-rtt-loss-matrix.csv`
- `paper/measurements/netns-dos-flood.csv`

If a script crashes mid-run, just re-invoke it: `setup_netns` tears down
stale state before recreating.

## 6. Platform metadata to record

When pasting numbers back, include:

```bash
uname -a
lscpu | grep -E "Model name|Architecture|CPU max MHz"
cat /etc/os-release | grep PRETTY_NAME
free -h | head -2
```

so the writeup can be unambiguous about which Pi revision and which
clock the numbers came from.

## 7. Copy results back

Once everything has run, commit (or just `scp`) the new CSVs and `.txt`
files. The five files we need on the Mac for thesis-text updates:

```
paper/measurements/pi-crypto-pq.txt
paper/measurements/pi-handshake-pq.txt
paper/measurements/pi-memory-pq.txt
paper/measurements/netns-mtu-sweep.csv
paper/measurements/netns-rtt-loss-matrix.csv
paper/measurements/netns-dos-flood.csv
```

(plus the vanilla counterparts for cross-mode comparisons in the discussion.)
