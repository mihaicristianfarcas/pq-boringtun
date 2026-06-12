//! handshake_benches — in-process handshake latency for all configurations.
//!
//! "Loopback" here means the two `Tunn` instances exchange bytes in memory
//! (no sockets, no OS scheduler), so this measures pure cryptographic cost.
//!
//! Methodology
//! -----------
//! * Criterion drives every measurement: each configuration gets its own
//!   warm-up phase, outlier detection, and bootstrapped 95% confidence
//!   intervals, so no configuration inherits caches or branch-predictor
//!   state warmed by another.
//! * In non-`pq` builds the registration order of `vanilla` vs `psk-slot`
//!   is randomised per run (coin flip from `OsRng`) so any residual
//!   ordering bias averages out across repeated invocations.
//! * Each iteration constructs a fresh pair of `Tunn` instances inside
//!   Criterion's `iter_batched` setup so setup cost is excluded from the
//!   measured time and so handshake state is realistic (cold per attempt).
//!
//! Runs
//! ----
//!   cargo bench --bench handshake_benches               # vanilla + PSK-slot
//!   cargo bench --bench handshake_benches --features pq # hybrid only
//!
//! The `pq` Cargo feature is a compile-time switch that routes every
//! handshake through the PQ path, so vanilla, PSK-slot, and hybrid have
//! to be measured from two separate binaries. Cache/branch-predictor
//! state never crosses that boundary.

use boringtun::noise::{Tunn, TunnResult};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

type HandshakeInput = (Tunn, Tunn, Vec<u8>, Vec<u8>);

fn make_pair(psk: Option<[u8; 32]>) -> HandshakeInput {
    let sk_a = StaticSecret::random_from_rng(OsRng);
    let pk_a = PublicKey::from(&sk_a);
    let sk_b = StaticSecret::random_from_rng(OsRng);
    let pk_b = PublicKey::from(&sk_b);
    let idx_a = OsRng.next_u32();
    let idx_b = OsRng.next_u32();

    let tun_a = Tunn::new(sk_a, pk_b, psk, None, idx_a, None);
    let tun_b = Tunn::new(sk_b, pk_a, psk, None, idx_b, None);

    (tun_a, tun_b, vec![0u8; 4096], vec![0u8; 4096])
}

fn run_handshake(input: HandshakeInput) {
    let (mut tun_a, mut tun_b, mut buf_a, mut buf_b) = input;

    let init = match tun_a.format_handshake_initiation(&mut buf_a, false) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("unexpected init result: {:?}", other),
    };

    let resp = match tun_b.decapsulate(None, &init, &mut buf_b) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("unexpected response result: {:?}", other),
    };

    let keepalive = match tun_a.decapsulate(None, &resp, &mut buf_a) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("unexpected keepalive result: {:?}", other),
    };

    match tun_b.decapsulate(None, &keepalive, &mut buf_b) {
        TunnResult::Done => {}
        other => panic!("unexpected final result: {:?}", other),
    }
}

#[cfg(not(feature = "pq"))]
fn handshake_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(500);

    // Randomise the registration order so ordering bias averages out across
    // repeated `cargo bench` invocations. With Criterion each function also
    // gets its own warm-up phase, so a single run is already robust to
    // cache/branch-predictor priming; this is belt-and-suspenders.
    let vanilla_first = (OsRng.next_u32() & 1) == 0;
    let order: [&str; 2] = if vanilla_first {
        ["vanilla", "psk_slot"]
    } else {
        ["psk_slot", "vanilla"]
    };

    let psk: [u8; 32] = {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    };

    for name in order {
        match name {
            "vanilla" => {
                group.bench_function("vanilla", |b| {
                    b.iter_batched(|| make_pair(None), run_handshake, BatchSize::SmallInput);
                });
            }
            "psk_slot" => {
                group.bench_function("psk_slot", |b| {
                    b.iter_batched(
                        || make_pair(Some(psk)),
                        run_handshake,
                        BatchSize::SmallInput,
                    );
                });
            }
            _ => unreachable!(),
        }
    }

    group.finish();
}

#[cfg(feature = "pq")]
fn handshake_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(500);

    // In a `--features pq` build every handshake takes the hybrid path,
    // so only the hybrid configuration is meaningful here.
    group.bench_function("hybrid", |b| {
        b.iter_batched(|| make_pair(None), run_handshake, BatchSize::SmallInput);
    });

    group.finish();
}

criterion_group!(benches, handshake_benches);
criterion_main!(benches);
