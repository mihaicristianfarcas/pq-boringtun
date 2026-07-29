# Phase 2 — static ML-KEM authentication

Two platforms, `cargo bench`, Criterion (500 samples per handshake/pre-auth
configuration, 1000 per primitive, bootstrapped 95 % CIs).

| | Apple M4 Pro, macOS 26.5.2 | Raspberry Pi 5 Model B rev 1.1, Debian, kernel 6.18.34 |
|---|---|---|
| core | Apple P-core, 4.5 GHz | Cortex-A76, 2.4 GHz |
| logs | `m4-*.txt` | `pi-*.txt` |

Raw logs alongside this file: `{m4,pi}-preauth-{pq,vanilla}.txt`,
`{m4,pi}-handshake-{pq,vanilla}-phase2.txt`, `{m4,pi}-crypto-phase2.txt`.

## Pre-authentication cost — the headline number

What a responder spends on one inbound initiation *before* it knows who sent
it. This is the flood budget an attacker gets to spend on the responder's
behalf, so it is the number that decides whether the design regresses
WireGuard's DoS resistance.

| initiation | asymmetric op before the identity is known | M4 | vs vanilla | Pi 5 | vs vanilla |
|---|---|---|---|---|---|
| classical (type 1) | X25519 DH | 21.85 µs | 1.00× | 196.78 µs | 1.00× |
| hybrid, ephemeral-only (type 5) | X25519 DH | 21.87 µs | 1.00× | 196.84 µs | 1.00× |
| static-auth (type 8) | ML-KEM-768 decapsulation | 31.76 µs | **1.45×** | 123.10 µs | **0.63×** |

**The sign of the result depends on the machine.** On Apple Silicon static
auth is a 1.45× DoS regression; on the Pi 5 it is a 0.63× improvement — a
responder does *less* work per unauthenticated packet than vanilla WireGuard.
Types 1 and 5 agree to within 0.03 % on both machines, as they must: they run
the identical X25519 path, which is the control for this comparison.

### Why the sign flips

The primitives, measured on the same machines in the same session
(`crypto_benches`, `x25519_shared_key_dalek` — the implementation the
handshake actually calls — and `mlkem768/decaps`):

| primitive | M4 | Pi 5 | Pi ÷ M4 |
|---|---|---|---|
| X25519 DH | 19.94 µs | 192.83 µs | 9.67× |
| ML-KEM-768 decapsulation | 27.66 µs | 116.02 µs | 4.19× |
| ML-KEM-768 encapsulation | 20.17 µs | 84.32 µs | 4.18× |
| ML-KEM-768 keygen | 24.07 µs | 82.23 µs | 3.42× |
| decaps ÷ DH | **1.39×** | **0.60×** | |

Moving from the M4 to the Pi costs X25519 9.7× but ML-KEM only 4.2×, and that
gap is the whole story. X25519's field arithmetic is a serial dependency chain
of 64×64→128 multiplies; the M4's wide out-of-order core and fast multipliers
hide that latency in a way the narrower Cortex-A76 cannot. ML-KEM-768's NTT is
16-bit arithmetic with abundant instruction-level parallelism, which the A76
handles comparatively well. So the ratio inverts.

Both primitives here are portable Rust with no hand-written assembly and no
NEON on either target, so this is a like-for-like comparison — but it also
means the ratio is a property of *these implementations*, not of the
algorithms. A NEON ML-KEM backend or an assembly X25519 would move it.

Message-level cost decomposes cleanly against the primitives:

| | M4 | Pi 5 |
|---|---|---|
| type 5: message − X25519 DH | 1.91 µs | 4.01 µs |
| type 8: message − ML-KEM decaps | 4.10 µs | 7.08 µs |
| difference (extra transcript hashing) | 2.19 µs | 3.07 µs |

The residual in each row is the two BLAKE2s chains and the ChaCha20-Poly1305
opens, common to all three configurations. Type 8 hashes ~2.3 KB more
transcript — the 1184-byte encapsulation key and the 1088-byte ciphertext —
which is what the difference row measures.

### What this means for DoS resistance

The regression case (Apple Silicon) stays modest, and two properties keep it
that way:

- The cost is constant and attacker-independent. ML-KEM decapsulation uses
  implicit rejection, so it never fails early and never branches on the
  ciphertext; there is no input an attacker can choose to make it slower.
- The mac1/mac2 cookie gate is unchanged and runs first. A 1.45× multiplier
  applies only to traffic that already passed the same rate limiter vanilla
  WireGuard relies on.

On the class of device the spec's original expectation came from — ARM
Cortex-A, here a Pi 5 — the design is what it predicted: a net DoS
*improvement*, because replacing an X25519 DH with an ML-KEM decapsulation
replaces the more expensive of the two primitives with the cheaper one.

## Handshake latency

Full handshake in process (both `Tunn`s in memory, no sockets), so this is
pure cryptographic cost.

| configuration | M4 | vs vanilla | Pi 5 | vs vanilla |
|---|---|---|---|---|
| vanilla | 154.96 µs | 1.00× | 1.3126 ms | 1.00× |
| PSK slot | 155.65 µs | 1.00× | 1.3128 ms | 1.00× |
| hybrid, ephemeral-only (types 5/6) | 248.26 µs | 1.60× | 1.6485 ms | 1.26× |
| static auth (types 8/9) | 366.71 µs | 2.37× | 2.1124 ms | 1.61× |
| static auth, segmented at MTU 1280 | 391.67 µs | 2.53× | 2.1540 ms | 1.64× |

Static auth's relative cost is *lower* on the Pi (1.61× vs 2.37×) for the same
reason the pre-auth number inverts: the vanilla baseline it is measured
against is dominated by X25519, which the Pi is disproportionately bad at.

Static auth adds one encapsulation and one decapsulation per direction over
the ephemeral-only hybrid:

| | M4 | Pi 5 |
|---|---|---|
| measured static − hybrid | 118.4 µs | 463.9 µs |
| predicted 2 × (encaps + decaps) | 95.7 µs | 400.7 µs |
| balance (transcript hashing, second keypair's bookkeeping) | 22.8 µs | 63.2 µs |

Segmentation at the IPv6 minimum costs 24.96 µs (6.8 %) on the M4 and 41.6 µs
(2.0 %) on the Pi on top of unsegmented static auth: splitting 2420 and 2268
bytes into 3 and 2 datagrams, with a keyed BLAKE2s tag over each. It is a
smaller *fraction* on the Pi only because the asymmetric work it sits on top
of is larger there.

## Message sizes

| message | phase 1 | static auth |
|---|---|---|
| initiation | 1332 B | 2420 B |
| response | 1180 B | 2268 B |
| segments at MTU 1500 | 1 / 1 | 2 / 2 |
| segments at MTU 1280 | 2 / 1 | 3 / 2 |

Segment 0 of a static-auth initiation is 1232 bytes of UDP payload — the
1172-byte authenticating prefix plus 60 bytes of segment overhead — which is
the IPv6 minimum MTU minus IPv6 and UDP headers, exactly. That equality is
what forced the field ordering; see §3 of the design spec.

## Reproducing

```
cargo bench -p boringtun --features pq --bench preauth_benches
cargo bench -p boringtun            --bench preauth_benches
cargo bench -p boringtun --features pq --bench handshake_benches
cargo bench -p boringtun            --bench handshake_benches
cargo bench -p boringtun --features pq --bench crypto_benches
```

`.cargo/config.toml` wraps test and bench binaries in `sudo -E`, which these do
not require. Override the runner for the host target:

- macOS: `CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env"`
- Pi: `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="env"`
