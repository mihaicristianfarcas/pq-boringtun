//! End-to-end PQ handshake over a real UDP path with a hard MTU ceiling.
//!
//! A relay socket sits between the two peers and *drops* any datagram larger
//! than the ceiling, which is what a low-MTU link does to an over-sized
//! packet once fragmentation is off the table. Nothing here is privileged:
//! no tun device, no root, just three UDP sockets and the public `Tunn` API.
//!
//! Run with: cargo test -p boringtun --features pq --test pq_path_mtu
#![cfg(feature = "pq")]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use rand_core::OsRng;

const MAX_UDP: usize = 4096;
/// IPv4 (20) + UDP (8). The MTU ceiling applies to the whole IP datagram.
const IP_UDP_OVERHEAD: usize = 28;

/// One end of the tunnel: a `Tunn` plus its socket, always talking to the
/// relay rather than directly to its peer.
struct Endpoint {
    tun: Tunn,
    sock: UdpSocket,
    relay: SocketAddr,
    sent: Vec<usize>,
}

impl Endpoint {
    fn send(&mut self, result: TunnResult) {
        match result {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(p) => {
                self.sent.push(p.len() + IP_UDP_OVERHEAD);
                self.sock.send_to(p, self.relay).unwrap();
            }
            TunnResult::WriteManyToNetwork(segs) => {
                for s in segs.iter() {
                    self.sent.push(s.len() + IP_UDP_OVERHEAD);
                    self.sock.send_to(s, self.relay).unwrap();
                }
            }
            TunnResult::Err(e) => panic!("tunnel error: {:?}", e),
            other => panic!("unexpected result: {:?}", other),
        }
    }
}

/// A UDP relay that enforces a path MTU. Returns the datagrams it dropped for
/// being too big, and every payload that reached a tunnel interface.
fn pump(
    a: &mut Endpoint,
    b: &mut Endpoint,
    relay: &UdpSocket,
    mtu: usize,
    rounds: usize,
) -> (usize, Vec<Vec<u8>>) {
    let a_addr = a.sock.local_addr().unwrap();
    let b_addr = b.sock.local_addr().unwrap();
    let mut buf = [0u8; MAX_UDP];
    let mut out = [0u8; MAX_UDP];
    let mut dropped = 0;
    let mut to_tunnel = vec![];

    for _ in 0..rounds {
        let (n, from) = match relay.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => break, // read timeout: nothing more in flight
        };
        if n + IP_UDP_OVERHEAD > mtu {
            dropped += 1;
            continue;
        }
        let (dst, to) = if from == a_addr {
            (&mut *b, b_addr)
        } else {
            (&mut *a, a_addr)
        };
        relay.send_to(&buf[..n], to).unwrap();

        // Let the receiving end react to what it just got
        let mut rbuf = [0u8; MAX_UDP];
        let (rn, _) = dst.sock.recv_from(&mut rbuf).unwrap();
        match dst.tun.decapsulate(None, &rbuf[..rn], &mut out) {
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                to_tunnel.push(p.to_vec())
            }
            other => dst.send(other),
        }
        // decapsulate() hands back one queued packet per call
        loop {
            match dst.tun.decapsulate(None, &[], &mut out) {
                TunnResult::Done => break,
                other => dst.send(other),
            }
        }
    }
    (dropped, to_tunnel)
}

struct Fixture {
    a: Endpoint,
    b: Endpoint,
    relay: UdpSocket,
}

/// Wire an existing fixture for static-KEM authentication (message types
/// 8/9), giving each side its own long-term ML-KEM keypair.
fn with_static_auth(f: &mut Fixture) {
    use boringtun::noise::handshake::{MlKemPublicKey, MlKemStaticSecret};
    use boringtun::noise::MLKEM768_SEED_SIZE;
    use rand_core::RngCore;
    use std::sync::Arc;

    fn keypair() -> Arc<MlKemStaticSecret> {
        let mut seed = [0u8; MLKEM768_SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        Arc::new(MlKemStaticSecret::from_seed(&seed))
    }

    let (a_mlkem, b_mlkem) = (keypair(), keypair());
    let a_ek = MlKemPublicKey::from_bytes(a_mlkem.encapsulation_key_bytes()).unwrap();
    let b_ek = MlKemPublicKey::from_bytes(b_mlkem.encapsulation_key_bytes()).unwrap();
    f.a.tun.set_pq_static_auth(a_mlkem, b_ek).unwrap();
    f.b.tun.set_pq_static_auth(b_mlkem, a_ek).unwrap();
}

fn fixture(mtu_a: u16, mtu_b: u16) -> Fixture {
    let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let b_public = x25519::PublicKey::from(&b_secret);

    let mut a_tun = Tunn::new(a_secret, b_public, None, None, 1, None);
    let mut b_tun = Tunn::new(b_secret, a_public, None, None, 2, None);
    a_tun.set_pq_path_mtu(mtu_a).unwrap();
    b_tun.set_pq_path_mtu(mtu_b).unwrap();

    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let mk = |tun| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        Endpoint {
            tun,
            sock,
            relay: relay_addr,
            sent: vec![],
        }
    };
    Fixture {
        a: mk(a_tun),
        b: mk(b_tun),
        relay,
    }
}

fn ipv4_packet() -> Vec<u8> {
    // 20-byte IPv4 header + 8-byte UDP header, src 10.0.0.1 dst 10.0.0.2
    let mut p = vec![
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    p.extend_from_slice(&[0x1f, 0x90, 0x1f, 0x91, 0, 8, 0, 0]);
    p
}

/// Drive a handshake and a data packet across the relay. Returns
/// (data reached the far side, datagrams dropped by the path).
fn run_through_path(f: &mut Fixture, mtu: usize) -> (bool, usize) {
    let mut out = [0u8; MAX_UDP];
    let packet = ipv4_packet();

    // A's first encapsulate queues the payload and emits the handshake
    let init = f.a.tun.encapsulate(&packet, &mut out);
    f.a.send(init);

    let (dropped, to_tunnel) = pump(&mut f.a, &mut f.b, &f.relay, mtu, 40);
    eprintln!(
        "path mtu {}: initiator sent {:?}, responder sent {:?}, dropped {}",
        mtu, f.a.sent, f.b.sent, dropped
    );

    // The payload A queued behind the handshake must surface on B's interface
    (to_tunnel.iter().any(|p| p == &packet), dropped)
}

/// Without segmentation the 1332-byte PQ initiation cannot cross a 1280-byte
/// path at all: the link drops it and the handshake never starts.
#[test]
fn pq_handshake_blocked_by_1280_path_without_segmentation() {
    let mut f = fixture(0, 0);
    let (delivered, dropped) = run_through_path(&mut f, 1280);
    assert!(!delivered, "handshake should not have completed");
    assert!(
        dropped > 0,
        "the path should have dropped the oversized init"
    );
    assert!(
        f.a.sent.iter().any(|&s| s > 1280),
        "initiator sent nothing oversized, so the test proved nothing"
    );
}

/// With pq_path_mtu set, every datagram fits and the tunnel comes up.
#[test]
fn pq_handshake_crosses_1280_path_when_segmented() {
    let mut f = fixture(1280, 1280);
    let (delivered, dropped) = run_through_path(&mut f, 1280);
    assert!(delivered, "data did not reach the far side");
    assert_eq!(dropped, 0, "the path dropped {} datagram(s)", dropped);
    assert!(
        f.a.sent.iter().all(|&s| s <= 1280) && f.b.sent.iter().all(|&s| s <= 1280),
        "a datagram exceeded the path MTU: a={:?} b={:?}",
        f.a.sent,
        f.b.sent
    );
}

/// The same at 576 bytes, the IPv4 minimum reassembly buffer.
#[test]
fn pq_handshake_crosses_576_path_when_segmented() {
    let mut f = fixture(576, 576);
    let (delivered, dropped) = run_through_path(&mut f, 576);
    assert!(delivered, "data did not reach the far side");
    assert_eq!(dropped, 0, "the path dropped {} datagram(s)", dropped);
    assert!(
        f.a.sent.iter().all(|&s| s <= 576) && f.b.sent.iter().all(|&s| s <= 576),
        "a datagram exceeded the path MTU: a={:?} b={:?}",
        f.a.sent,
        f.b.sent
    );
}

/// Static auth over a 1280-byte path: the 2420-byte initiation and the
/// 2268-byte response both cross a link that would otherwise pass neither.
/// This is the case the whole message layout was designed around — segment 0
/// carries the full 1172-byte authenticating prefix and lands at exactly
/// 1232 bytes of UDP payload.
#[test]
fn pqs_handshake_crosses_1280_path_when_segmented() {
    let mut f = fixture(1280, 1280);
    with_static_auth(&mut f);
    let (delivered, dropped) = run_through_path(&mut f, 1280);
    assert!(delivered, "data did not reach the far side");
    assert_eq!(dropped, 0, "the path dropped {} datagram(s)", dropped);
    assert!(
        f.a.sent.iter().all(|&s| s <= 1280) && f.b.sent.iter().all(|&s| s <= 1280),
        "a datagram exceeded the path MTU: a={:?} b={:?}",
        f.a.sent,
        f.b.sent
    );
    // The initiation is the first three datagrams the initiator sends (the
    // keepalive and the queued payload follow), and segment 0 carries exactly
    // 1232 bytes of UDP payload: the authenticating prefix plus its 60 bytes
    // of segment overhead, filling an IPv6-minimum path to the byte.
    assert!(f.a.sent.len() >= 3, "initiator datagrams: {:?}", f.a.sent);
    assert_eq!(f.a.sent[0] - IP_UDP_OVERHEAD, 1232);
    assert_eq!(f.b.sent.len(), 2, "responder datagrams: {:?}", f.b.sent);
}

/// Without segmentation a static-auth initiation cannot cross a 1500-byte
/// path either — it is 2420 bytes — so the tunnel never comes up.
#[test]
fn pqs_handshake_blocked_by_1500_path_without_segmentation() {
    let mut f = fixture(0, 0);
    with_static_auth(&mut f);
    let (delivered, dropped) = run_through_path(&mut f, 1500);
    assert!(!delivered, "handshake should not have completed");
    assert!(dropped > 0, "the path should have dropped the oversized init");
}

/// Static auth with only the initiator configured: the responder mirrors the
/// observed stride, exactly as it does for phase-1 messages.
#[test]
fn pqs_responder_mirrors_stride_across_1280_path() {
    let mut f = fixture(1280, 0);
    with_static_auth(&mut f);
    let (delivered, dropped) = run_through_path(&mut f, 1280);
    assert!(delivered, "data did not reach the far side");
    assert_eq!(dropped, 0, "the path dropped {} datagram(s)", dropped);
    assert!(
        f.b.sent.iter().all(|&s| s <= 1280),
        "unconfigured responder sent an oversized datagram: {:?}",
        f.b.sent
    );
}

/// Only the initiator is configured; the responder mirrors the stride it
/// observed, so its response fits the same path.
#[test]
fn pq_responder_mirrors_stride_across_576_path() {
    let mut f = fixture(576, 0);
    let (delivered, dropped) = run_through_path(&mut f, 576);
    assert!(delivered, "data did not reach the far side");
    assert_eq!(dropped, 0, "the path dropped {} datagram(s)", dropped);
    assert!(
        f.b.sent.iter().all(|&s| s <= 576),
        "unconfigured responder sent an oversized datagram: {:?}",
        f.b.sent
    );
}
