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
//!   cargo bench --bench handshake_benches --features pq # hybrid + static auth
//!
//! The `pq` Cargo feature is a compile-time switch that routes every
//! handshake through the PQ path, so vanilla, PSK-slot, and hybrid have
//! to be measured from two separate binaries. Cache/branch-predictor
//! state never crosses that boundary.
//!
//! Within a `pq` build, static-KEM authentication is per-peer configuration
//! rather than a compile-time switch, so `hybrid` and `static_auth` are
//! measured from the same binary. The segmented variant additionally pays
//! for splitting 2420 and 2268 bytes into three and two datagrams
//! respectively, which is what a 1280-byte path costs.

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

/// Every datagram a TunnResult wants on the wire. A segmented PQ handshake
/// message yields several; everything else yields zero or one.
fn datagrams(result: TunnResult) -> Vec<Vec<u8>> {
    match result {
        TunnResult::Done => vec![],
        TunnResult::WriteToNetwork(p) => vec![p.to_vec()],
        #[cfg(feature = "pq")]
        TunnResult::WriteManyToNetwork(segs) => segs.iter().map(|s| s.to_vec()).collect(),
        other => panic!("unexpected result: {:?}", other),
    }
}

fn run_handshake(input: HandshakeInput) {
    let (mut tun_a, mut tun_b, mut buf_a, mut buf_b) = input;

    let init = datagrams(tun_a.format_handshake_initiation(&mut buf_a, false));
    assert!(!init.is_empty(), "initiator produced nothing");

    let mut resp = vec![];
    for d in &init {
        resp.extend(datagrams(tun_b.decapsulate(None, d, &mut buf_b)));
    }
    assert!(!resp.is_empty(), "responder produced no response");

    let mut keepalive = vec![];
    for d in &resp {
        keepalive.extend(datagrams(tun_a.decapsulate(None, d, &mut buf_a)));
    }
    assert_eq!(keepalive.len(), 1, "expected exactly one keepalive");

    match tun_b.decapsulate(None, &keepalive[0], &mut buf_b) {
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

/// A pair wired for static-KEM authentication, optionally at a path MTU that
/// forces the handshake to be segmented.
#[cfg(feature = "pq")]
fn make_static_auth_pair(path_mtu: u16) -> HandshakeInput {
    use boringtun::noise::handshake::{MlKemPublicKey, MlKemStaticSecret};
    use boringtun::noise::MLKEM768_SEED_SIZE;
    use std::sync::Arc;

    fn keypair() -> Arc<MlKemStaticSecret> {
        let mut seed = [0u8; MLKEM768_SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        Arc::new(MlKemStaticSecret::from_seed(&seed))
    }

    let (mut tun_a, mut tun_b, buf_a, buf_b) = make_pair(None);
    let (a_mlkem, b_mlkem) = (keypair(), keypair());
    let a_ek = MlKemPublicKey::from_bytes(a_mlkem.encapsulation_key_bytes()).unwrap();
    let b_ek = MlKemPublicKey::from_bytes(b_mlkem.encapsulation_key_bytes()).unwrap();
    tun_a.set_pq_static_auth(a_mlkem, b_ek).unwrap();
    tun_b.set_pq_static_auth(b_mlkem, a_ek).unwrap();
    tun_a.set_pq_path_mtu(path_mtu).unwrap();
    tun_b.set_pq_path_mtu(path_mtu).unwrap();

    (tun_a, tun_b, buf_a, buf_b)
}

#[cfg(feature = "pq")]
fn handshake_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(500);

    // Ephemeral-only hybrid: the compile-time default for every peer in a
    // `--features pq` build.
    group.bench_function("hybrid", |b| {
        b.iter_batched(|| make_pair(None), run_handshake, BatchSize::SmallInput);
    });

    // Static-KEM authentication, unsegmented: adds one encapsulation and one
    // decapsulation per direction over `hybrid`.
    group.bench_function("static_auth", |b| {
        b.iter_batched(
            || make_static_auth_pair(0),
            run_handshake,
            BatchSize::SmallInput,
        );
    });

    // ...and over an IPv6-minimum path, where the same handshake is split
    // into 3 + 2 datagrams with a keyed BLAKE2s tag on each.
    group.bench_function("static_auth_segmented_1280", |b| {
        b.iter_batched(
            || make_static_auth_pair(1280),
            run_handshake,
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, handshake_benches);
criterion_main!(benches);
