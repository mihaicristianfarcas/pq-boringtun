# ML-KEM parameter sweep (Experiment #6)

All numbers are Criterion bootstrapped 95 % confidence intervals over 1000 samples.
Bench source: `boringtun/benches/crypto_benches/mlkem_benching.rs`.

Reproduce on macOS:

```
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" \
  CARGO_TARGET_DIR=/tmp/pq-bench-target \
  cargo bench --bench crypto_benches --features pq -- mlkem
```

Reproduce on Linux:

```
cargo bench --bench crypto_benches --features pq -- mlkem
```

## Latency

### Apple M4 (macOS Tahoe, aarch64)

| Param set    | Keygen (µs)            | Encaps (µs)            | Decaps (µs)            |
|--------------|------------------------|------------------------|------------------------|
| ML-KEM-512   | 14.69 [14.67, 14.72]   | 12.60 [12.58, 12.63]   | 17.45 [17.43, 17.48]   |
| ML-KEM-768   | 23.88 [23.86, 23.89]   | 20.67 [20.65, 20.68]   | 27.52 [27.49, 27.55]   |
| ML-KEM-1024  | 37.31 [37.27, 37.36]   | 31.25 [31.22, 31.29]   | 40.89 [40.83, 40.95]   |

### Raspberry Pi 5 (Debian 13, Cortex-A76 @ 2.4 GHz)

| Param set    | Keygen (µs)             | Encaps (µs)             | Decaps (µs)             |
|--------------|-------------------------|-------------------------|-------------------------|
| ML-KEM-512   | 48.32 [48.29, 48.38]    | 51.64 [51.64, 51.65]    | 74.70 [74.70, 74.71]    |
| ML-KEM-768   | 81.61 [81.60, 81.62]    | 84.04 [84.03, 84.04]    | 116.39 [116.28, 116.62] |
| ML-KEM-1024  | 125.61 [125.60, 125.63] | 127.80 [127.78, 127.81] | 167.42 [167.41, 167.43] |

### Ubuntu 26.04 / WSL2, AMD Ryzen 7 5700X (x86_64, AVX2)

| Param set    | Keygen (µs)            | Encaps (µs)            | Decaps (µs)            |
|--------------|------------------------|------------------------|------------------------|
| ML-KEM-512   | 20.94 [20.89, 21.00]   | 20.27 [20.22, 20.33]   | 28.88 [28.81, 28.96]   |
| ML-KEM-768   | 35.83 [35.75, 35.93]   | 33.88 [33.76, 34.01]   | 45.54 [45.43, 45.66]   |
| ML-KEM-1024  | 56.09 [55.97, 56.23]   | 51.41 [51.27, 51.57]   | 66.44 [66.29, 66.59]   |

## Observations

- **Scaling between security levels is roughly linear in security category.** Doubling
  the security category (512 → 1024) costs about 2.5× per op across all three
  platforms — a clean, predictable curve.
- **The x86_64 numbers come in between M4 and Pi**, despite being x86 against
  ARM. The Ryzen is consumer-grade and was running through the WSL2 hypervisor;
  the M4's wide out-of-order core comfortably out-paces it on ML-KEM by a factor
  of 1.4–1.5. The Pi is a further 2–3× slower than the Ryzen, which is the
  expected gap between a 2.4 GHz Cortex-A76 and a desktop-class core.

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
- The implementation in this thesis pins ML-KEM-768.

See `chapter9_discussion.tex` § "Parameter set agility" for the future-work
hook this table supports, and `chapter8_evaluation.tex` § "ML-KEM parameter
set sweep" for the in-thesis discussion.
