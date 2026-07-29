# Phase 2 — static ML-KEM authentication, M4 measurements

Apple M4, macOS 15, `cargo bench`, Criterion (500 samples per configuration,
bootstrapped 95 % CIs). Raw logs alongside this file:

- `m4-preauth-pq.txt`, `m4-preauth-vanilla.txt` — `preauth_benches`
- `m4-handshake-pq-phase2.txt`, `m4-handshake-vanilla-phase2.txt` — `handshake_benches`

## Pre-authentication cost — the headline number

What a responder spends on one inbound initiation *before* it knows who sent
it. This is the flood budget an attacker gets to spend on the responder's
behalf, so it is the number that decides whether the design regresses
WireGuard's DoS resistance.

| initiation | asymmetric op before the identity is known | mean | vs vanilla |
|---|---|---|---|
| classical (type 1) | X25519 DH | 21.85 µs | 1.00× |
| hybrid, ephemeral-only (type 5) | X25519 DH | 21.87 µs | 1.00× |
| static-auth (type 8) | ML-KEM-768 decapsulation | 31.76 µs | **1.45×** |

Decomposed against the primitives measured in the same session
(`crypto_benches`): X25519 DH 19.91 µs, ML-KEM-768 decapsulation 27.43 µs.
The remainder in each row is the two BLAKE2s chains and the
ChaCha20-Poly1305 open, which are common to all three — except that type 8
hashes ~2.3 KB more transcript (the 1184-byte encapsulation key and the
1088-byte ciphertext), which accounts for the extra ~2.4 µs on top of the
7.5 µs primitive gap.

**This refutes the hypothesis recorded in the design spec.** §3 of
`2026-07-28-static-mlkem-authentication-design.md` expected ML-KEM-768
decapsulation to be *cheaper* than an X25519 DH on ARM, making static auth a
DoS improvement over vanilla WireGuard. On the M4 it is 1.38× more expensive
at the primitive level and 1.45× at the message level. Static auth is
therefore a modest DoS *regression*, not an improvement.

Two things keep it modest rather than disqualifying:

- The cost is constant and attacker-independent. ML-KEM decapsulation uses
  implicit rejection, so it never fails early and never branches on the
  ciphertext; there is no input an attacker can choose to make it slower.
- The mac1/mac2 cookie gate is unchanged and runs first. A 1.45× multiplier
  applies only to traffic that already passed the same rate limiter vanilla
  WireGuard relies on.

Still to measure on the Raspberry Pi, where the X25519/ML-KEM ratio may differ
(the spec's expectation came from ARM Cortex-A figures, not Apple Silicon).

## Handshake latency

Full handshake in process (both `Tunn`s in memory, no sockets), so this is
pure cryptographic cost.

| configuration | mean | vs vanilla |
|---|---|---|
| vanilla | 154.96 µs | 1.00× |
| PSK slot | 155.65 µs | 1.00× |
| hybrid, ephemeral-only (types 5/6) | 248.26 µs | 1.60× |
| static auth (types 8/9) | 366.71 µs | 2.37× |
| static auth, segmented at MTU 1280 | 391.67 µs | 2.53× |

Static auth adds one encapsulation and one decapsulation per direction over
the ephemeral-only hybrid: 366.7 − 248.3 = 118.4 µs, against a predicted
2 × (20.67 encaps + 27.43 decaps) = 96.2 µs, the balance being the extra
transcript hashing and the second keypair's bookkeeping.

Segmentation at the IPv6 minimum costs 24.96 µs (6.8 %) on top: splitting
2420 and 2268 bytes into 3 and 2 datagrams, with a keyed BLAKE2s tag over
each.

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
cd boringtun
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" cargo bench --features pq --bench preauth_benches
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" cargo bench            --bench preauth_benches
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" cargo bench --features pq --bench handshake_benches
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" cargo bench            --bench handshake_benches
```

The runner override is needed because `.cargo/config.toml` wraps test and
bench binaries in `sudo -E`, which these do not require.
