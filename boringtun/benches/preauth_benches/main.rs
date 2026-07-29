//! preauth_benches — what a responder spends on an *unauthenticated* packet.
//!
//! This is the DoS-resistance measurement. For every inbound handshake
//! initiation, before it knows whether the sender is anyone it has heard of,
//! a WireGuard device must run one asymmetric operation and open one AEAD in
//! order to recover the claimed identity. That work is the flood budget an
//! attacker gets to spend on the responder's behalf, and it is the number to
//! watch when changing what goes into message 1.
//!
//! The three configurations differ in exactly one operation:
//!
//! | initiation | asymmetric op before the identity is known |
//! |---|---|
//! | classical (type 1) | X25519 DH (ephemeral × responder static) |
//! | hybrid, ephemeral-only (type 5) | X25519 DH (identical to vanilla) |
//! | static-auth (type 8) | ML-KEM-768 decapsulation |
//!
//! Everything else — the two BLAKE2s chains, the ChaCha20-Poly1305 open, the
//! peer-table lookup — is common to all three, so the delta between the bars
//! is the delta between an X25519 DH and an ML-KEM-768 decapsulation.
//!
//! The messages fed in are genuine initiations from *unrelated* initiators, so
//! they fail at the identity check. That is the attacker's cheapest path to
//! the responder's most expensive pre-authentication work: mac1 keys off the
//! responder's public static key and, for type 8, the static-KEM ciphertext is
//! made under the responder's published encapsulation key, so both gates are
//! passable by anyone who can read the configuration a peer would be given.
//!
//! Runs
//! ----
//!   cargo bench --bench preauth_benches               # classical only
//!   cargo bench --bench preauth_benches --features pq # all three
//!
//! `POOL` distinct messages are prepared up front and cycled through, so no
//! measurement re-parses bytes the previous one just touched.

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// Number of distinct initiations prepared per configuration
const POOL: usize = 64;

/// The responder's identity: what an attacker needs to know to get this far
struct Responder {
    secret: StaticSecret,
    public: PublicKey,
}

fn responder() -> Responder {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Responder { secret, public }
}

/// One initiation from a fresh, unrelated initiator toward `responder_public`
fn initiation(responder_public: PublicKey) -> Vec<u8> {
    let mut tun = Tunn::new(
        StaticSecret::random_from_rng(OsRng),
        responder_public,
        None,
        None,
        OsRng.next_u32(),
        None,
    );
    let mut dst = vec![0u8; 4096];
    match tun.format_handshake_initiation(&mut dst, true) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("unexpected initiation result: {:?}", other),
    }
}

fn preauth_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("preauth");
    group.sample_size(500);

    // In a non-`pq` build `format_handshake_initiation` emits type 1; in a
    // `pq` build it emits type 5. Either way this measures the X25519-DH
    // baseline that static auth is compared against.
    let r = responder();
    let pool: Vec<Vec<u8>> = (0..POOL).map(|_| initiation(r.public)).collect();
    let name = if cfg!(feature = "pq") {
        "hybrid_ephemeral_type5"
    } else {
        "classical_type1"
    };
    let mut i = 0usize;
    group.bench_function(name, |b| {
        b.iter_batched(
            || {
                i = (i + 1) % POOL;
                pool[i].clone()
            },
            |msg| {
                let packet = Tunn::parse_incoming_packet(&msg).unwrap();
                // The identity check fails — that is the point. What is being
                // measured is the work done getting there.
                let _ = parse_anon(&r, packet);
            },
            BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "pq")]
    static_auth_bench(&mut group, &r);

    group.finish();
}

/// Recover the claimed initiator identity, exactly as the device layer does
/// when it has to decide which peer a datagram belongs to.
fn parse_anon(r: &Responder, packet: Packet) -> bool {
    match packet {
        Packet::HandshakeInit(p) => parse_handshake_anon(&r.secret, &r.public, &p).is_ok(),
        #[cfg(feature = "pq")]
        Packet::PqHandshakeInit(p) => {
            boringtun::noise::handshake::parse_pq_handshake_anon(&r.secret, &r.public, &p).is_ok()
        }
        other => panic!("unexpected packet: {:?}", other),
    }
}

#[cfg(feature = "pq")]
fn static_auth_bench(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    r: &Responder,
) {
    use boringtun::noise::handshake::{
        parse_pqs_handshake_anon, MlKemPublicKey, MlKemStaticSecret,
    };
    use boringtun::noise::MLKEM768_SEED_SIZE;
    use std::sync::Arc;

    let responder_mlkem = Arc::new({
        let mut seed = [0u8; MLKEM768_SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        MlKemStaticSecret::from_seed(&seed)
    });
    let responder_ek = MlKemPublicKey::from_bytes(responder_mlkem.encapsulation_key_bytes())
        .expect("our own encapsulation key is well formed");

    // Each message comes from a different initiator, but all encapsulate to
    // the responder's published long-term key — which is public, so an
    // attacker can produce these at will.
    let pool: Vec<Vec<u8>> = (0..POOL)
        .map(|_| {
            let mut tun = Tunn::new(
                StaticSecret::random_from_rng(OsRng),
                r.public,
                None,
                None,
                OsRng.next_u32(),
                None,
            );
            let mut seed = [0u8; MLKEM768_SEED_SIZE];
            OsRng.fill_bytes(&mut seed);
            tun.set_pq_static_auth(
                Arc::new(MlKemStaticSecret::from_seed(&seed)),
                responder_ek.clone(),
            )
            .expect("no path MTU configured, so no floor applies");
            let mut dst = vec![0u8; 4096];
            match tun.format_handshake_initiation(&mut dst, true) {
                TunnResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("unexpected initiation result: {:?}", other),
            }
        })
        .collect();

    let mut i = 0usize;
    group.bench_function("static_auth_type8", |b| {
        b.iter_batched(
            || {
                i = (i + 1) % POOL;
                pool[i].clone()
            },
            |msg| {
                let packet = match Tunn::parse_incoming_packet(&msg).unwrap() {
                    Packet::PqsHandshakeInit(p) => p,
                    other => panic!("unexpected packet: {:?}", other),
                };
                // Succeeds in recovering an identity, which then matches no
                // configured peer. ML-KEM decapsulation uses implicit
                // rejection, so this cost is the same whether the ciphertext
                // is genuine or garbage.
                let _ = parse_pqs_handshake_anon(&responder_mlkem, &r.public, &packet);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, preauth_benches);
criterion_main!(benches);
