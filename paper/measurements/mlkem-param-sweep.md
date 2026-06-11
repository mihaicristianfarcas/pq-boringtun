# ML-KEM parameter sweep (Experiment #6)

All numbers are Criterion bootstrapped 95 % confidence intervals over 1000 samples.
Bench source: `boringtun/benches/crypto_benches/mlkem_benching.rs`.

Reproduce on macOS:

```
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" \
  CARGO_TARGET_DIR=/tmp/pq-bench-target \
  cargo bench --bench crypto_benches --features pq -- mlkem
```

Reproduce on Linux (no sudo runner needed if `.cargo/config.toml` is empty):

```
cargo bench --bench crypto_benches --features pq -- mlkem
```

## Latency

### Apple M4 (macOS 25, aarch64)

| Param set    | Keygen (µs)            | Encaps (µs)            | Decaps (µs)            |
|--------------|------------------------|------------------------|------------------------|
| ML-KEM-512   | 14.40 [14.39, 14.41]   | 12.71 [12.69, 12.72]   | 17.50 [17.48, 17.53]   |
| ML-KEM-768   | 23.85 [23.82, 23.87]   | 21.26 [21.21, 21.32]   | 27.99 [27.93, 28.06]   |
| ML-KEM-1024  | 36.84 [36.79, 36.89]   | 31.15 [31.13, 31.17]   | 40.79 [40.75, 40.84]   |

### Raspberry Pi 5 (Linux, aarch64)

_Pending — run on Pi and paste here._

### x86_64 (WSL2)

_Pending — run on Windows/WSL2 and paste here._

## Wire-format implications

If the rest of the WireGuard handshake layout is held constant and only the
embedded ML-KEM material is swapped, the hybrid datagram sizes are:

| Param set    | EK (B) | CT (B) | Hybrid init (B) | Hybrid response (B) |
|--------------|--------|--------|-----------------|---------------------|
| ML-KEM-512   |    800 |    768 |             948 |                 860 |
| ML-KEM-768   |   1184 |   1088 |            1332 |                1180 |
| ML-KEM-1024  |   1568 |   1568 |            1716 |                1660 |

- 1280-byte MTU floor (IPv6 minimum): only ML-KEM-512 fits without fragmentation.
- 1500-byte standard Ethernet MTU: ML-KEM-512 and ML-KEM-768 fit; ML-KEM-1024 must fragment.
- Existing hybrid implementation in this thesis pins ML-KEM-768.

See `chapter9_discussion.tex` § "Parameter set agility" for the future-work
hook this table supports.
