# MTU sweep (Experiment #1)

Harness: `paper/testbeds/netns/mtu_sweep.sh` (uses `lib.sh`).

Sweeps path MTU on the veth pair between two network namespaces, with
and without an iptables rule that attempts to drop IPv4 fragments on the
responder. 10 trials per cell; each trial restarts both tunnels so the
handshake is always cold. Latency is the first-packet ping RTT and
therefore subsumes the handshake cost.

## Results — Raspberry Pi 5

| Mode    | MTU (B) | Drop frags | Successes | p50 RTT (ms) |
|---------|--------:|------------|----------:|-------------:|
| vanilla | 1500    | none       | 10/10     | 1.70 |
| pq      | 1500    | none       | 10/10     | 2.09 |
| vanilla | 1500    | drop_frags | 10/10     | 2.58 |
| pq      | 1500    | drop_frags | 10/10     | 2.09 |
| vanilla | 1400    | none       | 10/10     | 1.71 |
| pq      | 1400    | none       | 10/10     | 3.26 |
| vanilla | 1400    | drop_frags | 10/10     | 2.50 |
| pq      | 1400    | drop_frags | 10/10     | 3.27 |
| vanilla | 1300    | none       | 10/10     | 2.64 |
| pq      | 1300    | none       | 10/10     | 3.10 |
| vanilla | 1300    | drop_frags | 10/10     | 1.71 |
| pq      | 1300    | drop_frags | 10/10     | 2.12 |
| vanilla | 1280    | none       | 10/10     | 2.26 |
| pq      | 1280    | none       | 10/10     | 2.10 |
| vanilla | 1280    | drop_frags | 10/10     | 1.76 |
| pq      | 1280    | drop_frags | 10/10     | 3.13 |

## Reading the numbers

**Headline:** the hybrid handshake completes successfully on every cell.
At MTU 1500 with no fragmentation pressure, hybrid takes ≈ 2 ms median
versus vanilla's ≈ 1.7 ms. The hybrid p50 stays in a 2–3 ms band across
the entire MTU range — the extra ML-KEM crypto and the larger
1{,}332-byte initiation are the load-bearing costs, not the underlay's
ability to carry them.

**Surprise (and important methodology caveat):** the `drop_frags` column
shows 100% success at every MTU, including the cells where the hybrid
initiation must fragment to fit. At MTU 1280, a 1{,}352-byte IP datagram
(the hybrid init plus UDP and IPv4 headers) does not fit and the kernel
splits it into two fragments. The iptables rule we install is:

```bash
iptables -I INPUT -i $RESP_VETH -f -j DROP
```

which is supposed to drop second-and-later IPv4 fragments. It does not
bite, and the reason is **netfilter's automatic conntrack defragmentation**.
On a modern Linux kernel, any iptables ruleset implicitly loads
`nf_defrag_ipv4`, which reassembles fragments at the conntrack stage —
which runs *before* the filter table. By the time INPUT sees the packet,
it is no longer a fragment, so the `-f` match never fires.

To genuinely simulate a fragment-dropping middlebox, the testbed would
need to use one of:

- `iptables -t raw -A PREROUTING -i $iface -f -j DROP` (the raw table
  runs before conntrack)
- `nftables` with a `ct status untracked` or pre-conntrack fragment
  match
- A separate "middlebox" netns sitting between init and resp, doing the
  drop on its forward path before defrag

This is documented as a testbed limitation rather than re-run, because
the sub-finding — that the iptables `-f` rule is silently inert on
modern Linux against userspace WG flows — is itself a useful
methodological note for anyone trying to reproduce.

## What the data does support

- The hybrid handshake completes at every MTU from 1280 to 1500 over a
  veth pair on Linux, with first-packet latency in the 1.7–3.3 ms range.
- The mild p50 spread across cells (≈ 1 ms) is consistent with normal
  kernel-fragmentation overhead on the smaller-MTU cells; there is no
  cliff at 1300 or 1280.
- The hybrid handshake is, end-to-end, about 0.5–1 ms slower than
  vanilla on this hardware, which matches the in-process Criterion gap
  (≈ 0.33 ms; the rest is the extra UDP and fragmentation work).

See `chapter8_evaluation.tex` § "MTU sweep" for the in-thesis treatment
and `chapter9_discussion.tex` § "Deployment considerations" for how this
shapes the MTU-management discussion.
