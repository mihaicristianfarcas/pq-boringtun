//! Per-peer memory footprint probe (Experiment #4).
//!
//! Prints the in-process peak RSS while holding N Tunn instances, in two
//! states: idle (no handshake started) and post-init (each Tunn has emitted
//! its handshake initiation, putting the state machine in `InitSent` and, for
//! pq builds, holding the ML-KEM decapsulation key in heap).
//!
//! Run once per build mode to quantify the ML-KEM contribution:
//!
//!     cargo run --release --example memory_probe
//!     cargo run --release --example memory_probe --features pq
//!
//! Output is CSV on stdout. The `# sizeof` lines are commentary; the data
//! rows have the header `mode,n,rss_idle_kb,rss_after_init_kb`.

use boringtun::noise::handshake::Handshake;
use boringtun::noise::Tunn;
use rand_core::OsRng;
use std::mem::size_of;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(target_os = "linux")]
fn peak_rss_kb() -> i64 {
    // On Linux, `ru_maxrss` is already in kilobytes.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
    }
    ru.ru_maxrss as i64
}

#[cfg(target_os = "macos")]
fn peak_rss_kb() -> i64 {
    // On macOS, `ru_maxrss` is in bytes; normalise to KB for parity with Linux.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
    }
    (ru.ru_maxrss as i64) / 1024
}

fn make_tunn(idx: u32) -> Tunn {
    let sk_local = StaticSecret::random_from_rng(OsRng);
    let sk_peer = StaticSecret::random_from_rng(OsRng);
    let pk_peer = PublicKey::from(&sk_peer);
    Tunn::new(sk_local, pk_peer, None, None, idx, None)
}

fn main() {
    let mode = if cfg!(feature = "pq") { "pq" } else { "vanilla" };

    eprintln!("# mode={mode}");
    eprintln!("# sizeof_Tunn={}", size_of::<Tunn>());
    eprintln!("# sizeof_Handshake={}", size_of::<Handshake>());
    eprintln!("# baseline_rss_kb={}", peak_rss_kb());

    println!("mode,n,rss_idle_kb,rss_after_init_kb");

    for &n in &[10usize, 100, 1000] {
        let mut tunns: Vec<Tunn> = (0..n).map(|i| make_tunn(i as u32)).collect();
        let rss_idle = peak_rss_kb();

        // Drive each Tunn into `InitSent`. For pq builds this also allocates
        // the ML-KEM decapsulation key on the heap (held until the response
        // arrives or the state expires), which is the peak per-peer cost.
        let mut buf = vec![0u8; 1500];
        for t in tunns.iter_mut() {
            let _ = t.format_handshake_initiation(&mut buf, false);
        }
        let rss_after = peak_rss_kb();

        println!("{mode},{n},{rss_idle},{rss_after}");
        drop(tunns);
    }
}
