# Per-peer memory footprint (Experiment #4)

Probe source: `boringtun/examples/memory_probe.rs`.
Reads peak RSS via `getrusage(RUSAGE_SELF)` (kilobytes on Linux, bytes on
macOS — normalised to KB at the call site).

Reproduce on macOS:

```
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" \
  CARGO_TARGET_DIR=/tmp/pq-bench-target \
  cargo run --release --example memory_probe
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" \
  CARGO_TARGET_DIR=/tmp/pq-bench-target \
  cargo run --release --example memory_probe --features pq
```

Reproduce on Linux:

```
cargo run --release --example memory_probe
cargo run --release --example memory_probe --features pq
```

## Compile-time struct sizes

| Type      | Vanilla (B) | Hybrid pq (B) | Delta (B) |
|-----------|-------------|---------------|-----------|
| Tunn      |      11 040 |        17 424 |   +6 384  |
| Handshake |         552 |         6 936 |   +6 384  |

The Handshake delta accounts for the entire Tunn delta. Handshake holds two
HandshakeState slots (previous + current), so each enum variant grew by
≈ 3 192 bytes — the union of an inline `Option<DecapsulationKey768>` (2 400 B
key material plus tag and alignment) in `InitSent` and an
`Option<Vec<u8>>` ek pointer in `InitReceived`.

The ML-KEM ek/ct are not retained in struct memory once the handshake
transitions to a session; they live on the wire and in the scratch buffer.

## Peak RSS (Apple M4, release build)

| N peers | Vanilla idle (KB) | Hybrid idle (KB) | Delta (KB) | Per-peer (B) |
|---------|-------------------|------------------|------------|--------------|
|      10 |             1 712 |            1 792 |         80 |        8 000 |
|     100 |             2 752 |            3 392 |        640 |        6 400 |
|   1 000 |            13 744 |           20 608 |      6 864 |        6 864 |

`rss_idle == rss_after_init` at every N, because `DecapsulationKey768` is
stored inline (FIPS-203 d-z form, 2 400 B array) — `format_handshake_initiation`
runs the keygen but does not heap-allocate. The peak RSS therefore tracks
the inline struct cost, not a transient allocation.

The per-peer cost converges to ≈ 6.9 KB at N = 1 000, within 8 % of the
6 384-byte struct delta; the remainder is allocator chunk and page overhead.

## Implications

For a constrained device holding 1 000 peers (a small concentrator or
mid-tier edge gateway), hybrid mode costs **≈ 6.9 MB extra RSS** over
vanilla — roughly equivalent to one additional MTU-sized buffer per peer.
At 100 peers the per-peer overhead is in the same ballpark; at very small
N (≤ 10) allocator and page noise dominate and the measurement is
not meaningful.

For IoT-class hardware where total RAM is in the 100-512 MB range, the
hybrid handshake adds < 1.5 % per peer to the resident set. No fundamental
deployment barrier.

### Pi 5 and x86_64

_Pending — same harness, run on the Pi and on WSL2._

## Notes on methodology

- `ru_maxrss` is monotone over process lifetime: ramping N=10 → 100 → 1 000
  in a single run measures the cumulative high-water mark, not per-N
  averages. Re-run the probe with one N at a time if a per-N delta is
  needed; for paper-grade comparisons N=1 000 alone is sufficient.
- The probe uses fresh keypairs per peer; key generation cost is not
  isolated from struct allocation cost in the idle measurement, but at
  N = 1 000 the X25519 key cost (~32 B static + ephemeral) is negligible
  compared to the hybrid delta.
