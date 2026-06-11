use criterion::{BatchSize, Criterion};
use ml_kem::kem::{Encapsulate, Kem, TryDecapsulate};
use ml_kem::{
    DecapsulationKey512, DecapsulationKey768, DecapsulationKey1024, EncapsulationKey512,
    EncapsulationKey768, EncapsulationKey1024, MlKem512, MlKem768, MlKem1024,
};

fn rng() -> rand_core_pq::UnwrapErr<getrandom_pq::SysRng> {
    rand_core_pq::UnwrapErr(getrandom_pq::SysRng)
}

// Each `bench_mlkemNNN` is structurally identical — keygen / encaps / decaps
// under the same Criterion harness, with `iter_batched` so input prep does not
// leak into the measured region. We keep them as separate functions (rather
// than a generic) because the ml-kem trait bounds for keying material across
// parameter sets are not uniform enough to make the generic form readable.

pub fn bench_mlkem512(c: &mut Criterion) {
    let mut group = c.benchmark_group("mlkem512");
    group.sample_size(1000);

    group.bench_function("keygen", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _: (DecapsulationKey512, EncapsulationKey512) =
                    MlKem512::generate_keypair_from_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    let (_dk_for_encaps, ek_for_encaps): (DecapsulationKey512, EncapsulationKey512) =
        MlKem512::generate_keypair_from_rng(&mut rng());
    group.bench_function("encaps", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _ = ek_for_encaps.encapsulate_with_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    let (dk_for_decaps, ek_for_decaps): (DecapsulationKey512, EncapsulationKey512) =
        MlKem512::generate_keypair_from_rng(&mut rng());
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

pub fn bench_mlkem1024(c: &mut Criterion) {
    let mut group = c.benchmark_group("mlkem1024");
    group.sample_size(1000);

    group.bench_function("keygen", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _: (DecapsulationKey1024, EncapsulationKey1024) =
                    MlKem1024::generate_keypair_from_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    let (_dk_for_encaps, ek_for_encaps): (DecapsulationKey1024, EncapsulationKey1024) =
        MlKem1024::generate_keypair_from_rng(&mut rng());
    group.bench_function("encaps", |b| {
        b.iter_batched(
            rng,
            |mut rng| {
                let _ = ek_for_encaps.encapsulate_with_rng(&mut rng);
            },
            BatchSize::SmallInput,
        );
    });

    let (dk_for_decaps, ek_for_decaps): (DecapsulationKey1024, EncapsulationKey1024) =
        MlKem1024::generate_keypair_from_rng(&mut rng());
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
