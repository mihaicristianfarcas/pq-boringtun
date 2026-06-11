//! Handshake-init flood generator (Experiment #3).
//!
//! Emits fresh WireGuard handshake initiation packets at a target rate
//! against a responder address. Each packet carries its own fresh keypair
//! (so the responder cannot fast-path them via session caches). MAC1 can
//! optionally be corrupted to test the responder's pre-Encaps rejection
//! path.
//!
//! Build:  cargo build --release --example handshake_flood [--features pq]
//!
//! Usage:
//!     handshake_flood <responder_udp_addr> <responder_static_pub_b64> \
//!         <duration_sec> <target_pps> <mac1_mode>
//!
//!   mac1_mode ∈ {valid, invalid}
//!
//! Prints `packets_sent=<N>` on stdout when finished.
//!
//! Feature-gating: builds in both vanilla and `pq` modes. In `pq` mode the
//! flood emits 1332-byte hybrid init packets; in vanilla mode 148-byte
//! classical init packets.

use boringtun::noise::Tunn;
use rand_core::OsRng;
use std::net::UdpSocket;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

fn parse_pubkey_b64(s: &str) -> [u8; 32] {
    let bytes = base64::decode(s).expect("invalid base64 public key");
    assert_eq!(bytes.len(), 32, "public key must decode to 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: handshake_flood <udp_addr> <resp_pub_b64> \
             <duration_sec> <target_pps> <valid|invalid>"
        );
        std::process::exit(2);
    }
    let target_addr = &args[1];
    let resp_pub_bytes = parse_pubkey_b64(&args[2]);
    let duration_sec: u64 = args[3].parse().expect("duration_sec");
    let target_pps: u64 = args[4].parse().expect("target_pps");
    let mac1_valid = match args[5].as_str() {
        "valid" => true,
        "invalid" => false,
        other => panic!("unknown mac1 mode: {}", other),
    };

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind UDP");
    sock.connect(target_addr).expect("connect UDP target");

    let resp_pub = PublicKey::from(resp_pub_bytes);

    // Format one packet to discover its size (148 vs 1332). Per-iteration
    // allocation is dominated by the keypair + handshake-state setup, not by
    // the buffer, so a single big scratch buffer is fine.
    let mut scratch = vec![0u8; 1500];

    // Rate limiter: track how many packets we are *allowed* to send by now.
    // If target_pps == 0, run unbounded (saturate the link).
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_sec);
    let mut sent: u64 = 0;
    let pacing = target_pps > 0;

    while Instant::now() < deadline {
        if pacing {
            let elapsed = start.elapsed().as_secs_f64();
            let allowed = (elapsed * target_pps as f64) as u64;
            if sent >= allowed {
                // Spin briefly. Sleep granularity at sub-ms is bad on Linux,
                // so we busy-wait — flood generators are expected to burn CPU.
                std::hint::spin_loop();
                continue;
            }
        }

        // Fresh keypair each iteration — the responder must do full crypto.
        let sk = StaticSecret::random_from_rng(OsRng);
        let mut tunn = Tunn::new(sk, resp_pub, None, None, sent as u32, None);

        let pkt = match tunn.format_handshake_initiation(&mut scratch, false) {
            boringtun::noise::TunnResult::WriteToNetwork(buf) => buf,
            other => panic!("unexpected format_handshake_initiation result: {:?}", other),
        };

        // Corrupt MAC1 if asked. MAC1 sits in [len-32, len-16].
        if !mac1_valid {
            let mac1_start = pkt.len() - 32;
            pkt[mac1_start] ^= 0xff;
        }

        // Best-effort: a full kernel UDP buffer just means we drop the packet
        // and move on, which is the right behaviour for a flood generator.
        let _ = sock.send(pkt);
        sent += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "packets_sent={} elapsed_sec={:.3} pps={:.0}",
        sent,
        elapsed,
        sent as f64 / elapsed
    );
}
