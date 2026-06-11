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
  Responder must run full crypto (Encaps in pq mode).
- `invalid` — MAC1 byte is flipped after format. Responder should reject
  before any Encaps work happens.

Responder CPU time is sampled before and after the flood window via
`/proc/<pid>/stat` utime+stime; the rate `cpu/pkt` is that delta divided
by the number of packets the flooder reported sent.

## Results — Raspberry Pi 5 (Cortex-A76 @ 2.4 GHz)

| Mode    | MAC1     | Packets sent | CPU (s) | cpu/pkt (µs) |
|---------|----------|--------------:|--------:|-------------:|
| vanilla | invalid  | 19{,}395 | 0.060 |   3.09 |
| vanilla | valid    | 19{,}424 | 0.290 |  14.93 |
| pq      | invalid  | 16{,}511 | 0.110 |   6.66 |
| pq      | valid    | 16{,}515 | 0.370 |  22.40 |

## Reading the numbers

The headline finding is the within-mode asymmetry between `invalid` and
`valid`:

| Mode    | valid / invalid ratio | meaning                                   |
|---------|----------------------:|-------------------------------------------|
| vanilla |                 4.8 × | full crypto path is 4.8 × the reject path |
| pq      |                 3.4 × | full crypto path is 3.4 × the reject path |

That ratio is the empirical confirmation that MAC1 verification short-circuits
before the expensive crypto. If MAC1 were checked after Encaps, the ratio
would be ≈ 1 — the reject path would carry the full crypto cost too. It
isn't, so it doesn't.

Cross-mode comparison (within MAC1 status):

| Path                   | vanilla | pq    | pq / vanilla |
|------------------------|--------:|------:|-------------:|
| invalid (reject only)  |   3.09  |  6.66 |        2.2 × |
| valid (full crypto)    |  14.93  | 22.40 |        1.5 × |

The pq reject path costs 2.2 × the vanilla one even though no Encaps is
done — the 1332-byte hybrid init takes more time to parse and to hash for
the rate-limit table lookup than the 148-byte vanilla init. But the
amplification from running the full pq crypto on top of that is modest:
pq valid is only 1.5 × pq invalid in raw terms, vs vanilla's 4.8 ×
penalty for being fooled into running full crypto.

## Headline throughput

The Pi sustained ≈ 16–19 K incoming inits per second from a saturating
single-threaded flooder over the 10-second window. At 22.40 µs per
packet (the worst case, pq valid), that consumes ≈ 37 ms of responder
CPU per second of wall time, or about 3.7 % of one core. The responder
has substantial headroom even at this saturation rate.

## What this does and does not measure

- It measures: per-packet CPU cost on the responder, by MAC1 status and
  handshake mode, with the cookie/MAC2 mechanism inactive (no
  load-triggered cookie replies were sent during the 10-second window).
- It does not measure: the cookie-reply path under sustained overload,
  which is the second line of defence that kicks in when the rate
  limiter detects flooding. That is a separate experiment.
- It does not measure: handshake completion under the flood. The
  flooder uses fresh keypairs per packet so no session is established
  even when MAC1 is valid; this is a CPU-cost experiment, not a
  goodput experiment.

See `chapter8_evaluation.tex` § "DoS asymmetry under handshake flood"
for the in-thesis discussion.
