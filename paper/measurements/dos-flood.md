# DoS asymmetry under handshake-init flood (Experiment #3)

Harness sources:
- Flooder: `boringtun/examples/handshake_flood.rs`
- Driver:  `paper/testbeds/netns/dos_flood.sh`

Methodology: a single responder boringtun-cli runs in one network namespace.
From a peer netns, the flooder emits handshake init packets at line rate
(`TARGET_PPS=0`, no pacing) for 10 seconds, each with a freshly generated
keypair so the responder cannot fast-path on a session cache. Two MAC1
modes:

- `valid`   — flooder uses the real responder public key, so MAC1 matches.
  The packet proceeds into the responder's load-dependent processing path.
- `invalid` — MAC1 byte is flipped after format. Responder rejects at the
  top of the receive path, before any further work.

Responder CPU time is sampled before and after the flood window via
`/proc/<pid>/stat` utime+stime; the rate `cpu/pkt` is that delta divided
by the number of packets the flooder reported sent.

Note that `packets_sent` is the **total over the 10-second window**, so the
sustained flood rate is ≈ 1.9 K pps (vanilla) / ≈ 1.65 K pps (pq). The
flooder, not the link, is the bottleneck: producing each packet costs a
real keypair generation plus MAC computation on the same class of core.

## Results — Raspberry Pi 5 (Cortex-A76 @ 2.4 GHz)

Canonical run: `netns-dos-flood.csv` (the run cited in the paper).

| Mode    | MAC1     | Packets sent | CPU (s) | cpu/pkt (µs) |
|---------|----------|--------------:|--------:|-------------:|
| vanilla | invalid  | 19{,}440 | 0.060 |   3.09 |
| vanilla | valid    | 19{,}427 | 0.290 |  14.93 |
| pq      | invalid  | 16{,}530 | 0.100 |   6.05 |
| pq      | valid    | 16{,}491 | 0.390 |  23.65 |

## What the `valid` path actually is

At these rates the responder sits permanently in the under-load regime.
BoringTun's rate limiter (`HANDSHAKE_RATE_LIMIT = 100`, reset every
second) admits at most 100 handshakes per second past the MAC1 check
without a cookie; every further valid-MAC1 packet gets only a cookie
reply, and the flooder never completes the cookie round-trip, so no
MAC2-authenticated retry follows. The admitted packets do not reach
ML-KEM either: the responder runs one X25519 DH to decrypt the
initiator's static key, finds no matching configured peer (the flood
responder has none), and drops the packet. Encaps only runs when a
response is built for a recognized peer.

So the `valid` rows are **not** the cost of full handshake crypto — a
single X25519 DH alone costs ≈ 192.5 µs on this hardware, an order of
magnitude above the measured 14.93 µs/pkt. They are: MAC1 verification
plus a cookie reply for ~95 % of packets, plus the rate-limited residue
of single-DH work. The accounting closes: at 1,943 pps, ~100 admitted
packets/s at ~195 µs each plus ~1,840 cookie replies/s at a few µs each
predict ≈ 29 ms of CPU per second — matching the measured 0.290 s over
the 10-second vanilla window.

## Reading the numbers

Within-mode asymmetry between `invalid` and `valid`:

| Mode    | valid / invalid ratio | meaning                                        |
|---------|----------------------:|------------------------------------------------|
| vanilla |                 4.8 × | verify+cookie path is 4.8 × the reject path    |
| pq      |                 3.9 × | verify+cookie path is 3.9 × the reject path    |

The security-relevant finding is stronger than a MAC1-ordering check:
under a saturating flood of well-formed, valid-MAC1 initiations the
responder performed **zero** ML-KEM operations, because MAC1
verification and cookie-based rate limiting together gate all
post-quantum work behind a round-trip the attacker must complete.

Cross-mode comparison (within MAC1 status):

| Path                   | vanilla | pq    | pq / vanilla |
|------------------------|--------:|------:|-------------:|
| invalid (reject only)  |   3.09  |  6.05 |        2.0 × |
| valid (verify+cookie)  |  14.93  | 23.65 |        1.6 × |

The pq reject path costs 2.0 × the vanilla one even though no Encaps is
done — the 1332-byte hybrid init takes more time to parse and to hash for
MAC1 verification than the 148-byte vanilla init. That is a message-size
cost, not a crypto cost.

## Headline throughput

The flooder saturated at ≈ 1.9 K inits/s (vanilla) and ≈ 1.65 K inits/s
(pq) over the 10-second window. At 23.65 µs per packet (the worst case,
pq valid), the responder consumes ≈ 39 ms of CPU per second of wall
time, or about 3.9 % of one core — substantial headroom even at
saturation.

## What this does and does not measure

- It measures: per-packet CPU cost on the responder, by MAC1 status and
  handshake mode, with the cookie-reply (under-load) path as the dominant
  response to valid-MAC1 packets beyond the 100/s admission threshold.
- It does not measure: the MAC2-authenticated path — an adversary who
  completes cookie round-trips from genuine source addresses can force
  full handshake processing (including Encaps in pq mode). Quantifying
  that path is a separate experiment.
- It does not measure: handshake completion under the flood. The
  flooder uses fresh keypairs per packet so no session is established
  even when MAC1 is valid; this is a CPU-cost experiment, not a
  goodput experiment.

See `chapter8_evaluation.tex` § "DoS asymmetry under handshake flood"
for the in-thesis discussion.
