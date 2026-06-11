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

## Compile-time struct sizes (identical across platforms)

| Type      | Vanilla (B) | Hybrid pq (B) | Delta (B) |
|-----------|-------------|---------------|-----------|
| Tunn      |      11 040 |        17 424 |   +6 384  |
| Handshake |         552 |         6 936 |   +6 384  |

Confirmed identical on all three measured platforms (Apple M4, Raspberry Pi
5, Ryzen 7 5700X via WSL2) — Rust struct layout is portable, so the
per-peer hybrid overhead is a fixed +6 384 bytes regardless of where the
binary runs.

The Handshake delta accounts for the entire Tunn delta. Handshake holds two
HandshakeState slots (previous + current), so each enum variant grew by
≈ 3 192 bytes — the union of an inline `Option<DecapsulationKey768>` (2 400 B
key material plus tag and alignment) in `InitSent` and an
`Option<Vec<u8>>` ek pointer in `InitReceived`.

The ML-KEM ek/ct are not retained in struct memory once the handshake
transitions to a session; they live on the wire and in the scratch buffer.

## Peak RSS at N peers

### Apple M4 (release build, macOS)

| N peers | Vanilla idle (KB) | Hybrid idle (KB) | Delta (KB) | Per-peer (B) |
|---------|-------------------|------------------|------------|--------------|
|      10 |             1 712 |            1 792 |         80 |        8 000 |
|     100 |             2 752 |            3 392 |        640 |        6 400 |
|   1 000 |            13 744 |           20 608 |      6 864 |        6 864 |

On the M4 the per-peer cost converges to ≈ 6.9 KB at N = 1 000, within 8 %
of the 6 384-byte struct delta; the remainder is allocator chunk and page
overhead.

### Raspberry Pi 5 (release build, Debian 13)

| N peers | Vanilla idle (KB) | Hybrid idle (KB) | Delta (KB) |
|---------|-------------------|------------------|------------|
|      10 |            52 480 |           52 992 |        512 |
|     100 |            52 480 |           52 992 |        512 |
|   1 000 |            52 480 |           52 992 |        512 |

### Ubuntu 26.04 / WSL2 (release build, Ryzen 7 5700X)

| N peers | Vanilla idle (KB) | Hybrid idle (KB) | Delta (KB) |
|---------|-------------------|------------------|------------|
|      10 |            64 464 |           65 136 |        672 |
|     100 |            64 464 |           65 136 |        672 |
|   1 000 |            64 464 |           65 136 |        672 |

## Why the Pi and x86_64 RSS is flat across N

The Linux numbers are honest, but the data they produce is uninteresting:
on both platforms the binary's static footprint (≈ 51 MB on the Pi, ≈ 63 MB
on the Ryzen) is large enough that the dynamic Tunn allocations at N =
1 000 fit inside the allocator arenas that were already mapped during
startup. `ru_maxrss` is a high-water mark and is page-granular, so adding
∼17 MB worth of Tunns to a process that already has ∼51 MB mapped does
not push the watermark up.

The cross-mode delta (vanilla → pq) of ≈ 0.5–0.7 MB does survive: it
reflects the additional static data the `ml-kem` crate brings in (NTT
constants, lookup tables, SHA-3 implementation), separate from the
per-peer cost.

**Headline number to cite in the thesis: the M4 per-peer measurement at
N = 1 000 (≈ 6.9 KB per peer overhead).** The Pi/x86_64 numbers confirm
that the struct sizes are platform-independent, which is what we actually
needed to know for portability.

## Implications

For a constrained device holding 1 000 peers (a small concentrator or
mid-tier edge gateway), hybrid mode costs **≈ 6.9 MB extra resident**
over vanilla — roughly equivalent to one additional MTU-sized buffer
per peer.

For IoT-class hardware where total RAM is in the 100–512 MB range, the
hybrid handshake adds well under 2 % per peer to the resident set. The
hybrid build's binary itself is also ~10–12 MB larger than vanilla
(the ml-kem crate plus its sha3 dependency), which matters more for
flash-constrained devices than RAM does.

## Notes on methodology

- `ru_maxrss` is monotone over process lifetime: ramping N=10 → 100 → 1 000
  in a single run measures the cumulative high-water mark, not per-N
  averages.
- macOS's `ru_maxrss` is reported in bytes (probe divides by 1024); Linux
  is already in kilobytes. The probe normalises so the table above is in
  KB throughout.
- The probe uses fresh keypairs per peer; key-generation cost is included
  in the idle measurement, but at N = 1 000 the X25519 key material (∼32 B
  static + ephemeral) is negligible compared to the Handshake struct
  itself.
