use criterion::{BatchSize, Criterion};
use ml_kem::kem::{Encapsulate, Kem, TryDecapsulate};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, MlKem768};

fn rng() -> rand_core_pq::UnwrapErr<getrandom_pq::SysRng> {
    rand_core_pq::UnwrapErr(getrandom_pq::SysRng)
}

pub fn bench_mlkem768(c: &mut Criterion) {
    let mut group = c.benchmark_group("mlkem768");
    group.sample_size(1000);

    group.bench_function("keygen", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _: (DecapsulationKey768, EncapsulationKey768) =
                    MlKem768::generate_keypair_from_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    // Encaps: keypair is fixed across iterations (only the input RNG varies),
    // matching ML-KEM's intended usage and the X25519 benches in this group.
    let (_dk_for_encaps, ek_for_encaps): (DecapsulationKey768, EncapsulationKey768) =
        MlKem768::generate_keypair_from_rng(&mut rng());
    group.bench_function("encaps", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _ = ek_for_encaps.encapsulate_with_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    // Decaps: fresh ciphertext per iteration so we exercise the full decap
    // path (including implicit rejection checks) without amortising input prep.
    let (dk_for_decaps, ek_for_decaps): (DecapsulationKey768, EncapsulationKey768) =
        MlKem768::generate_keypair_from_rng(&mut rng());
    group.bench_function("decaps", |b| {
        b.iter_batched(
            || {
                let (ct, _ss) = ek_for_decaps.encapsulate_with_rng(&mut rng());
                ct
            },
            |ct| {
                let _ = dk_for_decaps.try_decapsulate(&ct);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}
