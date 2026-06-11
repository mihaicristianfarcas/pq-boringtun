use blake2s_benching::{bench_blake2s_hash, bench_blake2s_hmac, bench_blake2s_keyed};
use chacha20poly1305_benching::bench_chacha20poly1305;
#[cfg(feature = "pq")]
use mlkem_benching::{bench_mlkem1024, bench_mlkem512, bench_mlkem768};
use x25519_public_key_benching::bench_x25519_public_key;
use x25519_shared_key_benching::bench_x25519_shared_key;

mod blake2s_benching;
mod chacha20poly1305_benching;
#[cfg(feature = "pq")]
mod mlkem_benching;
mod x25519_public_key_benching;
mod x25519_shared_key_benching;

#[cfg(not(feature = "pq"))]
criterion::criterion_group!(
    crypto_benches,
    bench_chacha20poly1305,
    bench_blake2s_hash,
    bench_blake2s_hmac,
    bench_blake2s_keyed,
    bench_x25519_shared_key,
    bench_x25519_public_key
);

#[cfg(feature = "pq")]
criterion::criterion_group!(
    crypto_benches,
    bench_chacha20poly1305,
    bench_blake2s_hash,
    bench_blake2s_hmac,
    bench_blake2s_keyed,
    bench_x25519_shared_key,
    bench_x25519_public_key,
    bench_mlkem512,
    bench_mlkem768,
    bench_mlkem1024
);

criterion::criterion_main!(crypto_benches);
