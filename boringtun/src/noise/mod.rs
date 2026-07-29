// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

mod session;
mod timers;

// Used by the device layer to expire stale PQ segment routing entries
#[cfg(all(feature = "pq", feature = "device"))]
pub(crate) use timers::REKEY_TIMEOUT;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
    /// A segmented PQ handshake message: every slice yielded by
    /// [`SegmentedMsg::iter`] must be sent as its own datagram, in order.
    #[cfg(feature = "pq")]
    WriteManyToNetwork(SegmentedMsg<'a>),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// A batch of type-7 segments packed contiguously at fixed stride into the
/// caller's destination buffer.
#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct SegmentedMsg<'a> {
    buf: &'a mut [u8],
    /// On-wire size of every segment except possibly the last
    seg_size: usize,
    /// On-wire size of the last segment
    last_size: usize,
    count: usize,
}

#[cfg(feature = "pq")]
impl<'a> SegmentedMsg<'a> {
    /// Iterate over the individual segments; each is one UDP datagram.
    /// Segment 0 comes first and must be transmitted first.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.count).map(move |i| {
            let off = i * self.seg_size;
            let len = if i + 1 == self.count {
                self.last_size
            } else {
                self.seg_size
            };
            &self.buf[off..off + len]
        })
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
    /// Operator-configured path MTU that PQ handshake messages must fit,
    /// 0 = never segment (default)
    #[cfg(feature = "pq")]
    pq_path_mtu: u16,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[cfg(feature = "pq")]
const PQ_HANDSHAKE_INIT: MessageType = 5;
#[cfg(feature = "pq")]
const PQ_HANDSHAKE_RESP: MessageType = 6;
#[cfg(feature = "pq")]
pub(crate) const MLKEM768_PK_SIZE: usize = 1184;
#[cfg(feature = "pq")]
pub(crate) const MLKEM768_CT_SIZE: usize = 1088;
/// FIPS 203 `(d, z)` seed, the storage form of a decapsulation key
#[cfg(feature = "pq")]
pub const MLKEM768_SEED_SIZE: usize = 64;
#[cfg(feature = "pq")]
const PQ_HANDSHAKE_INIT_SZ: usize = 1332; // 148 - 32 (MACs) + 1184 (ML-KEM ek) + 32 (MACs) = 116 + 1184 + 32
#[cfg(feature = "pq")]
const PQ_HANDSHAKE_RESP_SZ: usize = 1180; // 92 - 32 (MACs) + 1088 (ML-KEM ct) + 32 (MACs) = 60 + 1088 + 32

// Static-ML-KEM-authenticated handshake (message types 8/9). The static-KEM
// ciphertext precedes the encrypted identity so the identity is protected by
// ML-KEM rather than X25519; the X25519 ephemeral therefore has to sit *after*
// the authenticating prefix, which is what keeps segment 0 within a 1280-byte
// path (1172 + 60 = 1232, the IPv6 UDP payload limit, exactly).
#[cfg(feature = "pq")]
pub(crate) const PQS_HANDSHAKE_INIT: MessageType = 8;
#[cfg(feature = "pq")]
pub(crate) const PQS_HANDSHAKE_RESP: MessageType = 9;
/// type | sender_idx | mlkem_static_ct | encrypted_static | encrypted_timestamp
/// | unencrypted_ephemeral | mlkem_ephemeral_ek | mac1 | mac2
#[cfg(feature = "pq")]
pub(crate) const PQS_HANDSHAKE_INIT_SZ: usize = 2420;
/// type | sender_idx | receiver_idx | unencrypted_ephemeral | encrypted_nothing
/// | mlkem_ephemeral_ct | mlkem_static_ct | mac1 | mac2
#[cfg(feature = "pq")]
pub(crate) const PQS_HANDSHAKE_RESP_SZ: usize = 2268;
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_CT_S_OFF: usize = 8;
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_ENC_STATIC_OFF: usize = PQS_INIT_CT_S_OFF + MLKEM768_CT_SIZE; // 1096
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_ENC_TIMESTAMP_OFF: usize = PQS_INIT_ENC_STATIC_OFF + 32 + 16; // 1144
/// Everything that authenticates the initiator; must ride in segment 0
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_PREFIX_SZ: usize = PQS_INIT_ENC_TIMESTAMP_OFF + 12 + 16; // 1172
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_EPHEMERAL_OFF: usize = PQS_INIT_PREFIX_SZ; // 1172
#[cfg(feature = "pq")]
pub(crate) const PQS_INIT_EK_E_OFF: usize = PQS_INIT_EPHEMERAL_OFF + 32; // 1204
/// Same 60-byte classical prefix as the phase-1 response
#[cfg(feature = "pq")]
pub(crate) const PQS_RESP_PREFIX_SZ: usize = 60;
#[cfg(feature = "pq")]
pub(crate) const PQS_RESP_CT_E_OFF: usize = PQS_RESP_PREFIX_SZ; // 60
#[cfg(feature = "pq")]
pub(crate) const PQS_RESP_CT_S_OFF: usize = PQS_RESP_CT_E_OFF + MLKEM768_CT_SIZE; // 1148

// PQ handshake segmentation (message type 7). A type-7 segment is:
// type (u32 LE) | hs_id (u32 LE) | seg_idx (u8) | seg_cnt (u8) | 2 reserved
// zero bytes | 16-byte tag | chunk | mac1 | mac2
#[cfg(feature = "pq")]
pub(crate) const PQ_SEGMENT: MessageType = 7;
#[cfg(feature = "pq")]
pub(crate) const PQ_SEG_HDR_SZ: usize = 12;
#[cfg(feature = "pq")]
const PQ_SEG_TAG_SZ: usize = 16;
#[cfg(feature = "pq")]
const PQ_SEG_MACS_SZ: usize = 32;
#[cfg(feature = "pq")]
pub(crate) const PQ_SEG_CHUNK_OFF: usize = PQ_SEG_HDR_SZ + PQ_SEG_TAG_SZ;
/// Fixed per-segment overhead: header + tag + cookie MACs
#[cfg(feature = "pq")]
pub(crate) const PQ_SEG_OVERHEAD: usize = PQ_SEG_HDR_SZ + PQ_SEG_TAG_SZ + PQ_SEG_MACS_SZ;
#[cfg(feature = "pq")]
pub(crate) const PQ_MIN_SEG_CNT: usize = 2;
#[cfg(feature = "pq")]
pub(crate) const PQ_MAX_SEGMENTS: usize = 8;
/// Classical prefix of a PQ init: type, sender_idx, ephemeral,
/// encrypted_static, encrypted_timestamp
#[cfg(feature = "pq")]
pub(crate) const PQ_INIT_PREFIX_SZ: usize = 116;
/// Classical prefix of a PQ response: type, sender_idx, receiver_idx,
/// ephemeral, encrypted_nothing
#[cfg(feature = "pq")]
pub(crate) const PQ_RESP_PREFIX_SZ: usize = 60;
/// Worst-case IP (IPv6, 40) + UDP (8) overhead assumed when converting a path
/// MTU into a usable segment stride
#[cfg(feature = "pq")]
const PQ_IP_UDP_OVERHEAD: usize = 48;
/// Smallest accepted `pq_path_mtu`; guarantees segment 0 can carry the full
/// classical prefix with headroom. 0 disables segmentation entirely.
#[cfg(feature = "pq")]
pub const PQ_MIN_PATH_MTU: u16 = 256;
/// Smallest `pq_path_mtu` a static-auth peer can run on. Segment 0 must carry
/// the 1172-byte authenticating prefix, so
/// 1172 + 60 (segment overhead) + 48 (IPv6 + UDP) = 1280 exactly. No ML-KEM
/// parameter set has a small enough ciphertext to go below this, so
/// lower-MTU paths run the phase-1 ephemeral-only mode instead.
#[cfg(feature = "pq")]
pub const PQS_MIN_PATH_MTU: u16 = 1280;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct PqHandshakeInit<'a> {
    pub sender_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_timestamp: &'a [u8],
    pub mlkem_ephemeral_public: &'a [u8],
}

#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct PqHandshakeResponse<'a> {
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8],
    pub mlkem_ciphertext: &'a [u8],
}

#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct PqsHandshakeInit<'a> {
    pub sender_idx: u32,
    pub mlkem_static_ct: &'a [u8],
    pub encrypted_static: &'a [u8],
    pub encrypted_timestamp: &'a [u8],
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub mlkem_ephemeral_ek: &'a [u8],
}

#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct PqsHandshakeResponse<'a> {
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8],
    pub mlkem_ephemeral_ct: &'a [u8],
    pub mlkem_static_ct: &'a [u8],
}

/// One segment of a segmented PQ handshake message (type 7)
#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct PqSegment<'a> {
    /// Routing index: the initiator's sender_idx (init direction) or the
    /// response's receiver_idx (response direction)
    pub hs_id: u32,
    pub seg_idx: u8,
    pub seg_cnt: u8,
    /// Per-segment authenticator over header bytes 0..12 and the chunk
    pub tag: &'a [u8; 16],
    pub chunk: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
    #[cfg(feature = "pq")]
    PqHandshakeInit(PqHandshakeInit<'a>),
    #[cfg(feature = "pq")]
    PqHandshakeResponse(PqHandshakeResponse<'a>),
    #[cfg(feature = "pq")]
    PqsHandshakeInit(PqsHandshakeInit<'a>),
    #[cfg(feature = "pq")]
    PqsHandshakeResponse(PqsHandshakeResponse<'a>),
    #[cfg(feature = "pq")]
    PqSegment(PqSegment<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            #[cfg(feature = "pq")]
            (PQ_HANDSHAKE_INIT, PQ_HANDSHAKE_INIT_SZ) => {
                Packet::PqHandshakeInit(PqHandshakeInit {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    unencrypted_ephemeral: <&[u8; 32]>::try_from(&src[8..40])
                        .expect("length already checked above"),
                    encrypted_static: &src[40..88],
                    encrypted_timestamp: &src[88..116],
                    mlkem_ephemeral_public: &src[116..116 + MLKEM768_PK_SIZE],
                })
            }
            #[cfg(feature = "pq")]
            (PQ_HANDSHAKE_RESP, PQ_HANDSHAKE_RESP_SZ) => {
                Packet::PqHandshakeResponse(PqHandshakeResponse {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: <&[u8; 32]>::try_from(&src[12..44])
                        .expect("length already checked above"),
                    encrypted_nothing: &src[44..60],
                    mlkem_ciphertext: &src[60..60 + MLKEM768_CT_SIZE],
                })
            }
            #[cfg(feature = "pq")]
            (PQS_HANDSHAKE_INIT, PQS_HANDSHAKE_INIT_SZ) => {
                Packet::PqsHandshakeInit(PqsHandshakeInit {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    mlkem_static_ct: &src[PQS_INIT_CT_S_OFF..PQS_INIT_ENC_STATIC_OFF],
                    encrypted_static: &src[PQS_INIT_ENC_STATIC_OFF..PQS_INIT_ENC_TIMESTAMP_OFF],
                    encrypted_timestamp: &src[PQS_INIT_ENC_TIMESTAMP_OFF..PQS_INIT_PREFIX_SZ],
                    unencrypted_ephemeral: <&[u8; 32]>::try_from(
                        &src[PQS_INIT_EPHEMERAL_OFF..PQS_INIT_EK_E_OFF],
                    )
                    .expect("length already checked above"),
                    mlkem_ephemeral_ek: &src
                        [PQS_INIT_EK_E_OFF..PQS_INIT_EK_E_OFF + MLKEM768_PK_SIZE],
                })
            }
            #[cfg(feature = "pq")]
            (PQS_HANDSHAKE_RESP, PQS_HANDSHAKE_RESP_SZ) => {
                Packet::PqsHandshakeResponse(PqsHandshakeResponse {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: <&[u8; 32]>::try_from(&src[12..44])
                        .expect("length already checked above"),
                    encrypted_nothing: &src[44..PQS_RESP_PREFIX_SZ],
                    mlkem_ephemeral_ct: &src[PQS_RESP_CT_E_OFF..PQS_RESP_CT_S_OFF],
                    mlkem_static_ct: &src
                        [PQS_RESP_CT_S_OFF..PQS_RESP_CT_S_OFF + MLKEM768_CT_SIZE],
                })
            }
            #[cfg(feature = "pq")]
            (PQ_SEGMENT, len) if len > PQ_SEG_OVERHEAD => {
                let seg_idx = src[8];
                let seg_cnt = src[9];
                // Rigid header: reserved bytes zero, bounded segment count,
                // index within it
                if src[10] != 0
                    || src[11] != 0
                    || (seg_cnt as usize) < PQ_MIN_SEG_CNT
                    || (seg_cnt as usize) > PQ_MAX_SEGMENTS
                    || seg_idx >= seg_cnt
                {
                    return Err(WireGuardError::InvalidPacket);
                }
                Packet::PqSegment(PqSegment {
                    hs_id: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    seg_idx,
                    seg_cnt,
                    tag: <&[u8; 16]>::try_from(&src[PQ_SEG_HDR_SZ..PQ_SEG_CHUNK_OFF])
                        .expect("length already checked above"),
                    chunk: &src[PQ_SEG_CHUNK_OFF..len - PQ_SEG_MACS_SZ],
                })
            }
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),

            #[cfg(feature = "pq")]
            pq_path_mtu: 0,
        }
    }

    /// Configure the path MTU that PQ handshake messages must fit; messages
    /// exceeding it are split into type-7 segments. 0 (the default) disables
    /// segmentation; nonzero values below [`PQ_MIN_PATH_MTU`] are rejected,
    /// as are values below [`PQS_MIN_PATH_MTU`] once this peer is configured
    /// for static-KEM authentication.
    #[cfg(feature = "pq")]
    pub fn set_pq_path_mtu(&mut self, mtu: u16) -> Result<(), WireGuardError> {
        let floor = if self.handshake.pqs_enabled() {
            PQS_MIN_PATH_MTU
        } else {
            PQ_MIN_PATH_MTU
        };
        if mtu != 0 && mtu < floor {
            return Err(WireGuardError::InvalidParameter);
        }
        self.pq_path_mtu = mtu;
        Ok(())
    }

    /// Configure static-KEM authentication for this peer: our device's
    /// long-term ML-KEM-768 keypair and the peer's encapsulation key. Once
    /// set, this peer speaks message types 8/9 exclusively — inbound types 1,
    /// 2, 5 and 6 are dropped, so an attacker who breaks X25519 cannot
    /// downgrade the exchange.
    ///
    /// Rejected when the configured `pq_path_mtu` is below
    /// [`PQS_MIN_PATH_MTU`]: a static-auth initiation cannot be segmented
    /// onto such a path without buffering unauthenticated bytes.
    #[cfg(feature = "pq")]
    pub fn set_pq_static_auth(
        &mut self,
        static_mlkem: std::sync::Arc<handshake::MlKemStaticSecret>,
        peer_static_mlkem: handshake::MlKemPublicKey,
    ) -> Result<(), WireGuardError> {
        if self.pq_path_mtu != 0 && self.pq_path_mtu < PQS_MIN_PATH_MTU {
            return Err(WireGuardError::InvalidParameter);
        }
        self.handshake
            .set_pq_static_auth(static_mlkem, peer_static_mlkem);
        Ok(())
    }

    /// Whether this peer is configured for static-KEM authentication
    #[cfg(feature = "pq")]
    pub fn pq_static_auth_enabled(&self) -> bool {
        self.handshake.pqs_enabled()
    }

    /// The peer's configured long-term ML-KEM-768 encapsulation key, if any
    #[cfg(feature = "pq")]
    pub fn pq_peer_mlkem_public_key(&self) -> Option<&[u8; MLKEM768_PK_SIZE]> {
        self.handshake.peer_mlkem_public_key()
    }

    /// The stride to segment an outbound message of `msg_len` bytes with, or
    /// None when it should be sent unsegmented. The effective MTU is the
    /// minimum of our configured `pq_path_mtu` and the MTU implied by an
    /// inbound segmented initiation (responder stride mirroring).
    #[cfg(feature = "pq")]
    fn pq_stride_for(&self, msg_len: usize, observed_stride: Option<usize>) -> Option<usize> {
        let own_mtu = if self.pq_path_mtu == 0 {
            None
        } else {
            Some(self.pq_path_mtu as usize)
        };
        let observed_mtu = observed_stride.map(|s| s + PQ_SEG_OVERHEAD + PQ_IP_UDP_OVERHEAD);
        let effective = match (own_mtu, observed_mtu) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }?;
        if msg_len + PQ_IP_UDP_OVERHEAD > effective {
            Some(effective - PQ_IP_UDP_OVERHEAD - PQ_SEG_OVERHEAD)
        } else {
            None
        }
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32. It must also be large
    /// enough for a handshake initiation, since one may be emitted here: 148
    /// bytes classically, and in a `pq` build up to
    /// [`PQS_HANDSHAKE_INIT_SZ`] plus per-segment overhead when the message
    /// is segmented. A buffer of `MAX_UDP_SIZE`, as the device layer uses,
    /// always suffices.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        // Mode is per-peer configuration, never negotiated in band. A peer
        // configured for static-KEM authentication accepts nothing but types
        // 8/9 (and the type-7 segments carrying them), and a peer that is not
        // so configured accepts nothing that claims to be. Without this an
        // attacker who breaks X25519 could simply send a type-1 initiation
        // and bypass the entire post-quantum layer.
        #[cfg(feature = "pq")]
        {
            let pqs = self.handshake.pqs_enabled();
            let permitted = match &packet {
                Packet::HandshakeInit(_)
                | Packet::HandshakeResponse(_)
                | Packet::PqHandshakeInit(_)
                | Packet::PqHandshakeResponse(_) => !pqs,
                Packet::PqsHandshakeInit(_) | Packet::PqsHandshakeResponse(_) => pqs,
                _ => true,
            };
            if !permitted {
                return TunnResult::Err(WireGuardError::WrongPacketType);
            }
        }

        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
            #[cfg(feature = "pq")]
            Packet::PqHandshakeInit(p) => self.handle_pq_handshake_init(p, dst),
            #[cfg(feature = "pq")]
            Packet::PqHandshakeResponse(p) => self.handle_pq_handshake_response(p, dst),
            #[cfg(feature = "pq")]
            Packet::PqsHandshakeInit(p) => self.handle_pqs_handshake_init(p, dst),
            #[cfg(feature = "pq")]
            Packet::PqsHandshakeResponse(p) => self.handle_pqs_handshake_response(p, dst),
            #[cfg(feature = "pq")]
            Packet::PqSegment(p) => self.handle_pq_segment(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let keepalive_packet = session.format_packet_data(&[], dst);
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    #[cfg(feature = "pq")]
    fn handle_pq_handshake_init<'a>(
        &mut self,
        p: PqHandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received pq_handshake_initiation",
            remote_idx = p.sender_idx
        );

        self.handshake.receive_pq_handshake_initialization(p)?;

        self.pq_send_handshake_response(dst)
    }

    #[cfg(feature = "pq")]
    fn handle_pqs_handshake_init<'a>(
        &mut self,
        p: PqsHandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received pqs_handshake_initiation",
            remote_idx = p.sender_idx
        );

        self.handshake.receive_pqs_handshake_initialization(p)?;

        self.pq_send_handshake_response(dst)
    }

    #[cfg(feature = "pq")]
    fn handle_pqs_handshake_response<'a>(
        &mut self,
        p: PqsHandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received pqs_handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_pqs_handshake_response(p)?;
        Ok(self.establish_initiator_session(session, dst))
    }

    /// Store a freshly established initiator-side session and answer with a
    /// keepalive, which is what confirms the keys to the responder.
    #[cfg(feature = "pq")]
    fn establish_initiator_session<'a>(
        &mut self,
        session: session::Session,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        let keepalive_packet = session.format_packet_data(&[], dst);
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index);
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        TunnResult::WriteToNetwork(keepalive_packet)
    }

    /// Format the PQ handshake response for the current InitReceived state,
    /// segmenting it when our own `pq_path_mtu` requires it or the initiation
    /// arrived segmented (stride mirroring). Handles both the ephemeral-only
    /// (type 6) and static-auth (type 9) responses.
    #[cfg(feature = "pq")]
    fn pq_send_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let pqs = self.handshake.pqs_response_pending();
        let msg_sz = if pqs {
            PQS_HANDSHAKE_RESP_SZ
        } else {
            PQ_HANDSHAKE_RESP_SZ
        };
        let observed_stride = self.handshake.pq_observed_stride();
        let (result, session) = match self.pq_stride_for(msg_sz, observed_stride) {
            None => {
                let (packet, session, _seg_tag_key, _hs_id) = if pqs {
                    self.handshake.format_pqs_handshake_response(dst)?
                } else {
                    self.handshake.format_pq_handshake_response(dst)?
                };
                (TunnResult::WriteToNetwork(packet), session)
            }
            Some(stride) => {
                // Segment 0 must carry the whole response prefix; the shared
                // 60-byte prefix means both modes have the same floor
                if stride < PQS_RESP_PREFIX_SZ {
                    return Err(WireGuardError::InvalidParameter);
                }
                let mut scratch = [0u8; PQS_HANDSHAKE_RESP_SZ];
                let inner = &mut scratch[..msg_sz];
                let (_, session, seg_tag_key, hs_id) = if pqs {
                    self.handshake.format_pqs_handshake_response(inner)?
                } else {
                    self.handshake.format_pq_handshake_response(inner)?
                };
                let (count, seg_size, last_size) =
                    self.handshake
                        .segment_pq_message(inner, hs_id, stride, &seg_tag_key, dst)?;
                let buf_len = seg_size * (count - 1) + last_size;
                (
                    TunnResult::WriteManyToNetwork(SegmentedMsg {
                        buf: &mut dst[..buf_len],
                        seg_size,
                        last_size,
                        count,
                    }),
                    session,
                )
            }
        };

        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index);

        tracing::debug!(message = "Sending pq_handshake_response", local_idx = index);

        Ok(result)
    }

    /// Handle one type-7 segment: buffer it, and on completion of the inner
    /// message resume exactly where the unsegmented paths would.
    #[cfg(feature = "pq")]
    fn handle_pq_segment<'a>(
        &mut self,
        p: PqSegment,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::trace!(
            message = "Received pq_segment",
            hs_id = p.hs_id,
            seg_idx = p.seg_idx,
            seg_cnt = p.seg_cnt
        );

        match self.handshake.receive_pq_segment(&p)? {
            handshake::PqSegOutcome::Buffered => Ok(TunnResult::Done),
            handshake::PqSegOutcome::InitComplete => self.pq_send_handshake_response(dst),
            handshake::PqSegOutcome::RespComplete(session) => {
                Ok(self.establish_initiator_session(*session, dst))
            }
        }
    }

    #[cfg(feature = "pq")]
    fn handle_pq_handshake_response<'a>(
        &mut self,
        p: PqHandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received pq_handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_pq_handshake_response(p)?;
        Ok(self.establish_initiator_session(session, dst))
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        // The initiation type is fixed by this peer's configuration: static
        // auth (type 8) when an ML-KEM key pair is configured for it,
        // ephemeral-only hybrid (type 5) otherwise.
        #[cfg(feature = "pq")]
        let pqs = self.handshake.pqs_enabled();
        #[cfg(feature = "pq")]
        let (msg_sz, prefix_sz) = if pqs {
            (PQS_HANDSHAKE_INIT_SZ, PQS_INIT_PREFIX_SZ)
        } else {
            (PQ_HANDSHAKE_INIT_SZ, PQ_INIT_PREFIX_SZ)
        };

        // When the configured path MTU cannot carry the initiation in one
        // datagram, format it into a scratch buffer and emit type-7 segments
        #[cfg(feature = "pq")]
        if let Some(stride) = self.pq_stride_for(msg_sz, None) {
            // Segment 0 has to carry the whole authenticating prefix; if the
            // configured MTU cannot fit it, refuse to send rather than emit a
            // message the peer would have to buffer unauthenticated
            if stride < prefix_sz {
                return TunnResult::Err(WireGuardError::InvalidParameter);
            }
            let mut scratch = [0u8; PQS_HANDSHAKE_INIT_SZ];
            let inner = &mut scratch[..msg_sz];
            let formatted = if pqs {
                self.handshake.format_pqs_handshake_initiation(inner)
            } else {
                self.handshake.format_pq_handshake_initiation(inner)
            };
            if let Err(e) = formatted {
                return TunnResult::Err(e);
            }
            let (hs_id, seg_tag_key) = match self.handshake.current_init_seg_params() {
                Some(params) => params,
                None => return TunnResult::Err(WireGuardError::UnexpectedPacket),
            };
            let (count, seg_size, last_size) =
                match self
                    .handshake
                    .segment_pq_message(inner, hs_id, stride, &seg_tag_key, dst)
                {
                    Ok(v) => v,
                    Err(e) => return TunnResult::Err(e),
                };

            tracing::debug!(
                segments = count,
                "Sending segmented pq_handshake_initiation"
            );

            if starting_new_handshake {
                self.timer_tick(TimerName::TimeLastHandshakeStarted);
            }
            self.timer_tick(TimerName::TimeLastPacketSent);
            let buf_len = seg_size * (count - 1) + last_size;
            return TunnResult::WriteManyToNetwork(SegmentedMsg {
                buf: &mut dst[..buf_len],
                seg_size,
                last_size,
                count,
            });
        }

        #[cfg(feature = "pq")]
        let result = if pqs {
            self.handshake.format_pqs_handshake_initiation(dst)
        } else {
            self.handshake.format_pq_handshake_initiation(dst)
        };
        #[cfg(not(feature = "pq"))]
        let result = self.handshake.format_handshake_initiation(dst);

        match result {
            Ok(packet) => {
                // The pq build sends a different, ML-KEM-bearing initiation; log it
                // under its own name so the live strip can tell the two apart (the
                // receive side already logs "pq_handshake_response" distinctly).
                #[cfg(feature = "pq")]
                tracing::debug!("Sending pq_handshake_initiation");
                #[cfg(not(feature = "pq"))]
                tracing::debug!("Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 4096];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 4096];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 4096];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 4096];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        #[cfg(not(feature = "pq"))]
        assert!(matches!(packet, Packet::HandshakeInit(_)));
        #[cfg(feature = "pq")]
        assert!(matches!(packet, Packet::PqHandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        #[cfg(not(feature = "pq"))]
        assert!(matches!(packet, Packet::HandshakeInit(_)));
        #[cfg(feature = "pq")]
        assert!(matches!(packet, Packet::PqHandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(&resp).unwrap();
        #[cfg(not(feature = "pq"))]
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
        #[cfg(feature = "pq")]
        assert!(matches!(packet, Packet::PqHandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        #[cfg(not(feature = "pq"))]
        assert!(matches!(packet, Packet::HandshakeInit(_)));
        #[cfg(feature = "pq")]
        assert!(matches!(packet, Packet::PqHandshakeInit(_)));

        mock_instant::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    /// Validates the PSK-slot approach: two tunnels with a shared 32-byte PSK
    /// (simulating an ML-KEM-derived key) can complete a full handshake and
    /// exchange data packets. This proves zero boringtun code changes are needed
    /// for PSK-slot post-quantum protection.
    #[test]
    fn psk_slot_full_handshake_and_data() {
        // Simulate an ML-KEM-derived 32-byte PSK (any 32 bytes work)
        let psk: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10, 0xa0, 0xb1, 0xc2, 0xd3,
            0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b,
        ];

        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        // Both peers configured with the same PSK (3rd argument)
        let mut my_tun = Tunn::new(my_secret_key, their_public_key, Some(psk), None, my_idx, None);
        let mut their_tun = Tunn::new(their_secret_key, my_public_key, Some(psk), None, their_idx, None);

        // Full handshake: init -> response -> keepalive -> done
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        // Exchange a data packet to prove the session works
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];
        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    /// Verifies that mismatched PSKs cause handshake failure
    #[test]
    fn psk_slot_mismatched_psk_fails() {
        let psk_a: [u8; 32] = [0xaa; 32];
        let psk_b: [u8; 32] = [0xbb; 32];

        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        // Peers configured with different PSKs
        let mut my_tun = Tunn::new(my_secret_key, their_public_key, Some(psk_a), None, my_idx, None);
        let mut their_tun = Tunn::new(their_secret_key, my_public_key, Some(psk_b), None, their_idx, None);

        // Handshake init succeeds (PSK not yet involved)
        let init = create_handshake_init(&mut my_tun);

        // Response is generated (responder mixes their PSK)
        let mut dst = vec![0u8; 2048];
        let resp = their_tun.decapsulate(None, &init, &mut dst);
        assert!(matches!(resp, TunnResult::WriteToNetwork(_)));
        let resp = if let TunnResult::WriteToNetwork(sent) = resp {
            sent.to_vec()
        } else {
            unreachable!();
        };

        // Initiator tries to process response with different PSK — should fail
        let mut dst = vec![0u8; 2048];
        let result = my_tun.decapsulate(None, &resp, &mut dst);
        // Mismatched PSK causes AEAD decryption failure
        assert!(matches!(result, TunnResult::Err(_)));
    }

    // PQ-specific tests

    /// Verify PQ init is 1332 bytes and parses as PqHandshakeInit
    #[test]
    #[cfg(feature = "pq")]
    fn pq_handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), PQ_HANDSHAKE_INIT_SZ);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::PqHandshakeInit(_)));
    }

    /// Complete PQ handshake: init → response → keepalive → done
    #[test]
    #[cfg(feature = "pq")]
    fn pq_full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), PQ_HANDSHAKE_INIT_SZ);

        let resp = create_handshake_response(&mut their_tun, &init);
        assert_eq!(resp.len(), PQ_HANDSHAKE_RESP_SZ);

        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);
    }

    /// End-to-end: PQ handshake then send/receive one IP packet
    #[test]
    #[cfg(feature = "pq")]
    fn pq_one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    /// Vanilla tunnel rejects PQ type 5 packet (parsed as InvalidPacket)
    #[test]
    #[cfg(not(feature = "pq"))]
    fn vanilla_rejects_pq_packet() {
        // A packet with type=5 and size=1332 should be rejected without pq feature
        let mut packet = vec![0u8; 1332];
        packet[0..4].copy_from_slice(&5u32.to_le_bytes());
        let result = Tunn::parse_incoming_packet(&packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));
    }

    /// PQ handshake with PSK — both PQ and PSK active simultaneously
    #[test]
    #[cfg(feature = "pq")]
    fn pq_with_psk() {
        let psk: [u8; 32] = [0x42; 32];

        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let mut my_tun =
            Tunn::new(my_secret_key, their_public_key, Some(psk), None, my_idx, None);
        let mut their_tun =
            Tunn::new(their_secret_key, my_public_key, Some(psk), None, their_idx, None);

        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), PQ_HANDSHAKE_INIT_SZ);
        let resp = create_handshake_response(&mut their_tun, &init);
        assert_eq!(resp.len(), PQ_HANDSHAKE_RESP_SZ);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        // Verify data flows
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];
        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    /// A response whose ML-KEM ciphertext has been tampered with must not yield a
    /// completed handshake. The ciphertext is both covered by the message MAC and
    /// bound into key derivation (ML-KEM uses implicit rejection, so a corrupted
    /// ct decapsulates to a *different* shared secret rather than erroring, which
    /// desynchronises the chaining key and fails the response's AEAD tag). Either
    /// way the initiator must reject the response.
    #[test]
    #[cfg(feature = "pq")]
    fn pq_tampered_ciphertext_rejected() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let mut resp = create_handshake_response(&mut their_tun, &init);

        // Response layout: type(4) sender(4) receiver(4) ephemeral(32)
        // enc_nothing(16) ml_kem_ct(1088) macs(32). Flip bits inside the ct.
        let ct_start = 4 + 4 + 4 + 32 + 16;
        resp[ct_start + 50] ^= 0xff;

        let mut dst = [0u8; 1024];
        let result = my_tun.decapsulate(None, &resp, &mut dst);
        assert!(
            matches!(result, TunnResult::Err(_)),
            "tampered ML-KEM ciphertext must be rejected, got {:?}",
            result
        );
    }

    /// Compile-time guarantee backing the forward-secrecy argument: the ephemeral
    /// ML-KEM decapsulation key wipes its secret material on drop, so no
    /// recoverable dk remains once the handshake completes. This bound only holds
    /// because the `pq` feature enables `ml-kem/zeroize`; if that feature were
    /// dropped, this test would fail to compile.
    #[test]
    #[cfg(feature = "pq")]
    fn mlkem_decapsulation_key_zeroized_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ml_kem::DecapsulationKey768>();
    }

    // ---- PQ handshake segmentation tests ----

    /// Collect the datagrams a TunnResult wants on the wire
    #[cfg(feature = "pq")]
    fn collect_datagrams(result: TunnResult) -> Vec<Vec<u8>> {
        match result {
            TunnResult::Done => vec![],
            TunnResult::WriteToNetwork(p) => vec![p.to_vec()],
            TunnResult::WriteManyToNetwork(segs) => segs.iter().map(|s| s.to_vec()).collect(),
            r => panic!("unexpected result {:?}", r),
        }
    }

    #[cfg(feature = "pq")]
    fn create_two_tuns_mtu(mtu_a: u16, mtu_b: u16) -> (Tunn, Tunn) {
        let (mut a, mut b) = create_two_tuns();
        a.set_pq_path_mtu(mtu_a).unwrap();
        b.set_pq_path_mtu(mtu_b).unwrap();
        (a, b)
    }

    /// Format a handshake initiation and return its wire datagrams
    #[cfg(feature = "pq")]
    fn initiation_datagrams(tun: &mut Tunn) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; 4096];
        let dgrams = collect_datagrams(tun.format_handshake_initiation(&mut dst, true));
        assert!(!dgrams.is_empty());
        dgrams
    }

    /// Feed one datagram; panics on TunnResult::Err
    #[cfg(feature = "pq")]
    fn feed(tun: &mut Tunn, dgram: &[u8]) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; 4096];
        let res = tun.decapsulate(None, dgram, &mut dst);
        if let TunnResult::Err(e) = res {
            panic!("unexpected decapsulate error {:?}", e);
        }
        collect_datagrams(res)
    }

    /// Feed one datagram, expecting it to be dropped (silently or with a
    /// local error); asserts nothing was sent in reaction
    #[cfg(feature = "pq")]
    fn feed_expect_drop(tun: &mut Tunn, dgram: &[u8]) {
        let mut dst = vec![0u8; 4096];
        match tun.decapsulate(None, dgram, &mut dst) {
            TunnResult::Err(_) | TunnResult::Done => {}
            r => panic!("packet should have been dropped, got {:?}", r),
        }
    }

    /// Recompute mac1 after tampering with a handshake message/segment, the
    /// same way an observe+inject attacker can (mac1 keys off the receiver's
    /// public static key only). mac2 is zeroed (not under load).
    #[cfg(feature = "pq")]
    fn restamp_mac1(packet: &mut [u8], receiver_static_public: &x25519_dalek::PublicKey) {
        use crate::noise::handshake::{b2s_hash, b2s_keyed_mac_16, LABEL_MAC1};
        let mac1_off = packet.len() - 32;
        let mac1_key = b2s_hash(LABEL_MAC1, receiver_static_public.as_bytes());
        let mac1 = b2s_keyed_mac_16(&mac1_key, &packet[..mac1_off]);
        packet[mac1_off..mac1_off + 16].copy_from_slice(&mac1);
        for b in &mut packet[mac1_off + 16..] {
            *b = 0;
        }
    }

    /// Drive a full handshake + one data packet through the given datagram
    /// streams and assert everything decrypts
    #[cfg(feature = "pq")]
    fn complete_handshake_and_data(my_tun: &mut Tunn, their_tun: &mut Tunn) {
        let init = initiation_datagrams(my_tun);
        let mut resp = vec![];
        for d in &init {
            resp.extend(feed(their_tun, d));
        }
        assert!(!resp.is_empty(), "responder produced no response");
        let mut keepalive = vec![];
        for d in &resp {
            keepalive.extend(feed(my_tun, d));
        }
        assert_eq!(keepalive.len(), 1, "initiator should send one keepalive");
        for d in &keepalive {
            assert!(feed(their_tun, d).is_empty());
        }

        // Data flows both ways
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];
        let packet = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&packet, &mut my_dst);
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            panic!("no session after segmented handshake: {:?}", data);
        };
        let recv = their_tun.decapsulate(None, data, &mut their_dst);
        let recv = if let TunnResult::WriteToTunnelV4(r, _) = recv {
            r
        } else {
            panic!("data packet did not decrypt: {:?}", recv);
        };
        assert_eq!(&packet[..], recv);
    }

    /// pq_path_mtu validation: 0 disables, 1..255 rejected, >=256 accepted
    #[test]
    #[cfg(feature = "pq")]
    fn pq_path_mtu_validation() {
        let (mut tun, _) = create_two_tuns();
        assert!(tun.set_pq_path_mtu(0).is_ok());
        assert!(tun.set_pq_path_mtu(1).is_err());
        assert!(tun.set_pq_path_mtu(255).is_err());
        assert!(tun.set_pq_path_mtu(256).is_ok());
        assert!(tun.set_pq_path_mtu(1280).is_ok());
    }

    /// At 1280 (IPv6 minimum): init splits into 2 segments, response stays
    /// unsegmented (1228 bytes on wire <= 1280)
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segmented_handshake_1280_both() {
        let (mut a, mut b) = create_two_tuns_mtu(1280, 1280);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 2);
        // stride = 1280 - 48 - 60 = 1172; wire sizes 1232 and 220
        assert_eq!(init[0].len(), 1232);
        assert_eq!(init[1].len(), 1332 - 1172 + 60);
        assert!(init.iter().all(|d| d.len() + 48 <= 1280));

        assert!(feed(&mut b, &init[0]).is_empty());
        let resp = feed(&mut b, &init[1]);
        assert_eq!(resp.len(), 1, "response must be unsegmented at 1280");
        assert_eq!(resp[0].len(), PQ_HANDSHAKE_RESP_SZ);

        let keepalive = feed(&mut a, &resp[0]);
        assert_eq!(keepalive.len(), 1);
        assert!(feed(&mut b, &keepalive[0]).is_empty());
    }

    /// At 576: init and response both split into 3 segments; full handshake
    /// and data exchange work
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segmented_handshake_576_both() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 3);
        assert!(init.iter().all(|d| d.len() + 48 <= 576));

        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[1]).is_empty());
        let resp = feed(&mut b, &init[2]);
        assert_eq!(resp.len(), 3, "response must be segmented at 576");
        assert!(resp.iter().all(|d| d.len() + 48 <= 576));

        assert!(feed(&mut a, &resp[0]).is_empty());
        assert!(feed(&mut a, &resp[1]).is_empty());
        let keepalive = feed(&mut a, &resp[2]);
        assert_eq!(keepalive.len(), 1);
        assert!(feed(&mut b, &keepalive[0]).is_empty());
    }

    /// Full handshake + data at 1280 and 576, both-sided configuration
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segmented_full_exchange() {
        for mtu in [1280u16, 576] {
            let (mut a, mut b) = create_two_tuns_mtu(mtu, mtu);
            complete_handshake_and_data(&mut a, &mut b);
        }
    }

    /// Single-sided configuration: only the initiator segments; the responder
    /// mirrors the observed stride and, at 1280, still answers unsegmented
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segmented_initiator_only() {
        let (mut a, mut b) = create_two_tuns_mtu(1280, 0);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 2);
        assert!(feed(&mut b, &init[0]).is_empty());
        let resp = feed(&mut b, &init[1]);
        assert_eq!(resp.len(), 1);
        let keepalive = feed(&mut a, &resp[0]);
        assert_eq!(keepalive.len(), 1);

        // At 576 the mirrored stride forces a segmented response too
        let (mut a, mut b) = create_two_tuns_mtu(576, 0);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 3);
        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[1]).is_empty());
        let resp = feed(&mut b, &init[2]);
        assert_eq!(resp.len(), 3, "responder must mirror the inbound stride");
        complete_handshake_tail(&mut a, &mut b, &resp);
    }

    /// Responder-only configuration: init goes out unsegmented, the response
    /// is segmented per the responder's own path MTU
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segmented_responder_only() {
        let (mut a, mut b) = create_two_tuns_mtu(0, 576);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 1);
        assert_eq!(init[0].len(), PQ_HANDSHAKE_INIT_SZ);
        let resp = feed(&mut b, &init[0]);
        assert_eq!(resp.len(), 3);
        complete_handshake_tail(&mut a, &mut b, &resp);
    }

    #[cfg(feature = "pq")]
    fn complete_handshake_tail(a: &mut Tunn, b: &mut Tunn, resp: &[Vec<u8>]) {
        let mut keepalive = vec![];
        for d in resp {
            keepalive.extend(feed(a, d));
        }
        assert_eq!(keepalive.len(), 1);
        assert!(feed(b, &keepalive[0]).is_empty());
    }

    /// Segments 1..n may arrive in any order within the burst
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segments_out_of_order() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 3);
        // Segment 0 first (protocol requirement), then the tail reversed
        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[2]).is_empty());
        let resp = feed(&mut b, &init[1]);
        assert_eq!(resp.len(), 3);
        complete_handshake_tail(&mut a, &mut b, &resp);
    }

    /// A segment arriving before its segment 0 has no routing entry and is
    /// dropped silently; the burst still completes when re-sent in order
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segment_before_seg0_dropped() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init = initiation_datagrams(&mut a);
        feed_expect_drop(&mut b, &init[1]);
        // Full burst in order still completes
        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[1]).is_empty());
        let resp = feed(&mut b, &init[2]);
        assert_eq!(resp.len(), 3);
    }

    /// Duplicate segments are dropped (slots are write-once) without
    /// disturbing reassembly
    #[test]
    #[cfg(feature = "pq")]
    fn pq_duplicate_segment_dropped() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init = initiation_datagrams(&mut a);
        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[1]).is_empty());
        feed_expect_drop(&mut b, &init[1]); // duplicate
        let resp = feed(&mut b, &init[2]);
        assert_eq!(resp.len(), 3);
    }

    /// A missing segment means no completion and no response
    #[test]
    #[cfg(feature = "pq")]
    fn pq_missing_segment_no_completion() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init = initiation_datagrams(&mut a);
        assert!(feed(&mut b, &init[0]).is_empty());
        assert!(feed(&mut b, &init[2]).is_empty());
        // init[1] never arrives; nothing must have been sent and no session
        // must exist on the responder
        let mut dst = [0u8; 2048];
        let sent = b.encapsulate(&[], &mut dst);
        assert!(
            !matches!(sent, TunnResult::WriteToNetwork(p) if p[0] == 4),
            "responder must not have a session"
        );
    }

    /// A forged segment with valid mac1 but corrupted payload fails the
    /// per-segment tag, buffers nothing, and the real handshake completes
    #[test]
    #[cfg(feature = "pq")]
    fn pq_forged_segment_bad_tag_buffers_nothing() {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let mut a = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        let mut b = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        a.set_pq_path_mtu(576).unwrap();
        b.set_pq_path_mtu(576).unwrap();

        let init = initiation_datagrams(&mut a);
        assert!(feed(&mut b, &init[0]).is_empty());

        // Attacker corrupts a chunk byte in segment 1 and restamps mac1
        let mut forged = init[1].clone();
        forged[PQ_SEG_CHUNK_OFF + 5] ^= 0xff;
        restamp_mac1(&mut forged, &their_public_key);
        feed_expect_drop(&mut b, &forged);

        // Header tampering: flip seg_cnt on segment 1 and restamp mac1
        let mut forged = init[1].clone();
        forged[9] = 4; // real seg_cnt is 3
        restamp_mac1(&mut forged, &their_public_key);
        feed_expect_drop(&mut b, &forged);

        // The genuine segments still complete the handshake
        assert!(feed(&mut b, &init[1]).is_empty());
        let resp = feed(&mut b, &init[2]);
        assert_eq!(resp.len(), 3);
        complete_handshake_tail(&mut a, &mut b, &resp);
    }

    /// §5 regression: an observer truncating a captured type-5 init,
    /// retyping it to 1 and recomputing mac1 must be rejected under the
    /// classical chain WITHOUT consuming the timestamp — the genuine init
    /// must still be accepted afterwards.
    #[test]
    #[cfg(feature = "pq")]
    fn pq_truncate_retype_rejected_without_timestamp_burn() {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let mut a = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        let mut b = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );

        let init = create_handshake_init(&mut a);
        assert_eq!(init.len(), PQ_HANDSHAKE_INIT_SZ);

        // Truncate to classical size, retype to 1, recompute mac1
        let mut forged = init[..HANDSHAKE_INIT_SZ].to_vec();
        forged[0] = HANDSHAKE_INIT as u8;
        restamp_mac1(&mut forged, &their_public_key);
        feed_expect_drop(&mut b, &forged);

        // The real init must still complete (timestamp was not consumed)
        let resp = feed(&mut b, &init);
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].len(), PQ_HANDSHAKE_RESP_SZ);
    }

    /// §5 guard: a classical type-2 response against an outstanding PQ
    /// initiation is rejected by the state machine, not just by AEAD failure
    #[test]
    #[cfg(feature = "pq")]
    fn pq_classical_response_rejected_by_guard() {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let mut a = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );

        let init = create_handshake_init(&mut a);
        let initiator_index = u32::from_le_bytes(init[4..8].try_into().unwrap());

        // Forge a classical response addressed at the outstanding PQ init
        let mut forged = vec![0u8; HANDSHAKE_RESP_SZ];
        forged[0..4].copy_from_slice(&HANDSHAKE_RESP.to_le_bytes());
        forged[4..8].copy_from_slice(&999u32.to_le_bytes());
        forged[8..12].copy_from_slice(&initiator_index.to_le_bytes());
        // any 32 bytes parse as an ephemeral
        forged[12..44].copy_from_slice(&[7u8; 32]);
        restamp_mac1(&mut forged, &my_public_key);

        let mut dst = [0u8; 2048];
        let res = a.decapsulate(None, &forged, &mut dst);
        assert!(
            matches!(res, TunnResult::Err(WireGuardError::WrongPacketType)),
            "guard must reject the classical response explicitly, got {:?}",
            res
        );
    }

    /// Swapping the responder ephemeral in response segment 0 changes the
    /// tag-key anchor, so the tag fails and nothing is buffered; the genuine
    /// response still completes the handshake
    #[test]
    #[cfg(feature = "pq")]
    fn pq_response_ephemeral_swap_rejected() {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let mut a = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        let mut b = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        a.set_pq_path_mtu(576).unwrap();
        b.set_pq_path_mtu(576).unwrap();

        let init = initiation_datagrams(&mut a);
        let mut resp = vec![];
        for d in &init {
            resp.extend(feed(&mut b, d));
        }
        assert_eq!(resp.len(), 3);

        // Tamper the ephemeral inside response segment 0's chunk
        let mut forged = resp[0].clone();
        forged[PQ_SEG_CHUNK_OFF + 12] ^= 0xff;
        restamp_mac1(&mut forged, &my_public_key);
        feed_expect_drop(&mut a, &forged);

        // Genuine response still completes
        complete_handshake_tail(&mut a, &mut b, &resp);
    }

    /// Segments replayed from a previous handshake are rejected: segment 0
    /// by the timestamp replay check, later segments for lack of a slot
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segment_replay_from_previous_handshake() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let old_init = initiation_datagrams(&mut a);
        let mut resp = vec![];
        for d in &old_init {
            resp.extend(feed(&mut b, d));
        }
        complete_handshake_tail(&mut a, &mut b, &resp);

        // Replay the old segments against the completed responder
        feed_expect_drop(&mut b, &old_init[0]);
        feed_expect_drop(&mut b, &old_init[1]);

        // A fresh handshake still works (advance the mock clock so the new
        // initiation carries a later timestamp than the replayed one)
        #[cfg(feature = "mock-instant")]
        mock_instant::MockClock::advance(Duration::from_secs(1));
        complete_handshake_and_data(&mut a, &mut b);
    }

    /// The partial-init slot is a single slot: a newer authenticated
    /// segment 0 replaces the old partial and the new handshake completes
    #[test]
    #[cfg(feature = "pq")]
    fn pq_partial_init_slot_replacement() {
        let (mut a, mut b) = create_two_tuns_mtu(576, 576);
        let init_a = initiation_datagrams(&mut a);
        assert!(feed(&mut b, &init_a[0]).is_empty());

        // Initiator retransmits: a fresh handshake with fresh index and keys
        // (under mock-instant the clock must move for a fresh timestamp)
        #[cfg(feature = "mock-instant")]
        mock_instant::MockClock::advance(Duration::from_secs(1));
        let init_b = initiation_datagrams(&mut a);
        assert!(feed(&mut b, &init_b[0]).is_empty());
        assert!(feed(&mut b, &init_b[1]).is_empty());
        let resp = feed(&mut b, &init_b[2]);
        assert_eq!(resp.len(), 3);
        complete_handshake_tail(&mut a, &mut b, &resp);

        // Leftover segments of the replaced handshake are now dropped
        feed_expect_drop(&mut b, &init_a[1]);
    }

    /// With pq_path_mtu unset the wire behavior is unsegmented end to end
    #[test]
    #[cfg(feature = "pq")]
    fn pq_unset_mtu_never_segments() {
        let (mut a, mut b) = create_two_tuns();
        let init = initiation_datagrams(&mut a);
        assert_eq!(init.len(), 1);
        assert_eq!(init[0].len(), PQ_HANDSHAKE_INIT_SZ);
        let resp = feed(&mut b, &init[0]);
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].len(), PQ_HANDSHAKE_RESP_SZ);
    }

    /// The device routes an inbound segment 0 to a peer by decrypting the
    /// inner init's static field, exactly as it does for an unsegmented
    /// init. Segments 1..n and response-direction segments carry no static
    /// field, so the same call must fail and let the device fall back to its
    /// receiver-index table.
    #[test]
    #[cfg(feature = "pq")]
    fn pq_segment0_peer_lookup() {
        use crate::noise::handshake::parse_pq_segment0_anon;

        let a_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let a_public = x25519_dalek::PublicKey::from(&a_secret);
        let b_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let b_public = x25519_dalek::PublicKey::from(&b_secret);

        let mut a = Tunn::new(a_secret, b_public, None, None, OsRng.next_u32(), None);
        let mut b = Tunn::new(
            b_secret.clone(),
            a_public,
            None,
            None,
            OsRng.next_u32(),
            None,
        );
        // 576 segments both directions
        a.set_pq_path_mtu(576).unwrap();
        b.set_pq_path_mtu(576).unwrap();

        /// The chunk a device hands to the anon parser: everything between the
        /// segment header+tag and the trailing mac1/mac2
        fn chunk_of(dgram: &[u8]) -> &[u8] {
            &dgram[PQ_SEG_CHUNK_OFF..dgram.len() - PQ_SEG_MACS_SZ]
        }

        let init = initiation_datagrams(&mut a);
        assert!(init.len() > 1, "expected a segmented init");

        // Segment 0 identifies the initiator to the responder
        let hh = parse_pq_segment0_anon(&b_secret, &b_public, chunk_of(&init[0]))
            .expect("segment 0 should resolve the initiator's static key");
        assert_eq!(hh.peer_static_public, *a_public.as_bytes());

        // Later segments carry ciphertext only
        for seg in &init[1..] {
            assert!(parse_pq_segment0_anon(&b_secret, &b_public, chunk_of(seg)).is_err());
        }

        // Response-direction segment 0 has no static field either: the device
        // falls back to peers_by_idx for it
        let mut resp = vec![];
        for d in &init {
            resp.extend(feed(&mut b, d));
        }
        assert!(resp.len() > 1, "expected a segmented response");
        for seg in &resp {
            assert!(parse_pq_segment0_anon(&b_secret, &b_public, chunk_of(seg)).is_err());
        }

        // ...and the handshake still completes over those segments
        let mut keepalive = vec![];
        for d in &resp {
            keepalive.extend(feed(&mut a, d));
        }
        assert_eq!(keepalive.len(), 1);
    }

    // ---- Static ML-KEM authentication (message types 8/9) ----

    /// A pair of tunnels wired for static-KEM authentication, keeping the key
    /// material around so tests can restamp MACs and drive the anon parsers
    /// the way the device layer does.
    #[cfg(feature = "pq")]
    struct StaticAuthPair {
        a: Tunn,
        b: Tunn,
        a_public: x25519_dalek::PublicKey,
        b_public: x25519_dalek::PublicKey,
        a_mlkem: std::sync::Arc<crate::noise::handshake::MlKemStaticSecret>,
        b_mlkem: std::sync::Arc<crate::noise::handshake::MlKemStaticSecret>,
    }

    #[cfg(feature = "pq")]
    fn random_mlkem_secret() -> crate::noise::handshake::MlKemStaticSecret {
        let mut seed = [0u8; MLKEM768_SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        crate::noise::handshake::MlKemStaticSecret::from_seed(&seed)
    }

    #[cfg(feature = "pq")]
    fn ek_of(
        s: &crate::noise::handshake::MlKemStaticSecret,
    ) -> crate::noise::handshake::MlKemPublicKey {
        crate::noise::handshake::MlKemPublicKey::from_bytes(s.encapsulation_key_bytes()).unwrap()
    }

    #[cfg(feature = "pq")]
    fn static_auth_pair(mtu_a: u16, mtu_b: u16) -> StaticAuthPair {
        use std::sync::Arc;

        let a_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let a_public = x25519_dalek::PublicKey::from(&a_secret);
        let b_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let b_public = x25519_dalek::PublicKey::from(&b_secret);

        let mut a = Tunn::new(a_secret, b_public, None, None, OsRng.next_u32(), None);
        let mut b = Tunn::new(b_secret, a_public, None, None, OsRng.next_u32(), None);

        let a_mlkem = Arc::new(random_mlkem_secret());
        let b_mlkem = Arc::new(random_mlkem_secret());
        a.set_pq_static_auth(Arc::clone(&a_mlkem), ek_of(&b_mlkem))
            .unwrap();
        b.set_pq_static_auth(Arc::clone(&b_mlkem), ek_of(&a_mlkem))
            .unwrap();
        a.set_pq_path_mtu(mtu_a).unwrap();
        b.set_pq_path_mtu(mtu_b).unwrap();

        StaticAuthPair {
            a,
            b,
            a_public,
            b_public,
            a_mlkem,
            b_mlkem,
        }
    }

    /// Unsegmented static-auth handshake: sizes match the spec and both
    /// message types parse.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_full_handshake() {
        let mut p = static_auth_pair(0, 0);

        let init = create_handshake_init(&mut p.a);
        assert_eq!(init.len(), PQS_HANDSHAKE_INIT_SZ);
        assert!(matches!(
            Tunn::parse_incoming_packet(&init).unwrap(),
            Packet::PqsHandshakeInit(_)
        ));

        let resp = create_handshake_response(&mut p.b, &init);
        assert_eq!(resp.len(), PQS_HANDSHAKE_RESP_SZ);
        assert!(matches!(
            Tunn::parse_incoming_packet(&resp).unwrap(),
            Packet::PqsHandshakeResponse(_)
        ));

        let keepalive = parse_handshake_resp(&mut p.a, &resp);
        parse_keepalive(&mut p.b, &keepalive);
    }

    /// End-to-end data over a static-auth session, unsegmented and segmented,
    /// with the MTU configured on one side or both
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_full_exchange_all_mtus() {
        for (mtu_a, mtu_b) in [
            (0u16, 0u16),
            (1280, 1280),
            (1500, 1500),
            (1280, 0),
            (0, 1280),
            (1500, 1280),
        ] {
            let mut p = static_auth_pair(mtu_a, mtu_b);
            complete_handshake_and_data(&mut p.a, &mut p.b);
        }
    }

    /// At the IPv6 minimum the init splits into 3 segments and segment 0 is
    /// exactly 1232 bytes — the UDP payload limit — with the whole 1172-byte
    /// authenticating prefix inside it. This is the arithmetic the whole
    /// message layout was chosen for.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_segmented_at_1280_fits_exactly() {
        let mut p = static_auth_pair(1280, 1280);
        let init = initiation_datagrams(&mut p.a);
        assert_eq!(init.len(), 3);
        assert_eq!(init[0].len(), 1232);
        assert_eq!(init[0].len() - PQ_SEG_OVERHEAD, PQS_INIT_PREFIX_SZ);
        assert!(init.iter().all(|d| d.len() + 48 <= 1280));

        assert!(feed(&mut p.b, &init[0]).is_empty());
        assert!(feed(&mut p.b, &init[1]).is_empty());
        let resp = feed(&mut p.b, &init[2]);
        assert_eq!(resp.len(), 2, "response splits in two at 1280");
        assert!(resp.iter().all(|d| d.len() + 48 <= 1280));

        assert!(feed(&mut p.a, &resp[0]).is_empty());
        let keepalive = feed(&mut p.a, &resp[1]);
        assert_eq!(keepalive.len(), 1);
        assert!(feed(&mut p.b, &keepalive[0]).is_empty());
    }

    /// At 1500 both directions fit in two segments
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_segmented_at_1500() {
        let mut p = static_auth_pair(1500, 1500);
        let init = initiation_datagrams(&mut p.a);
        assert_eq!(init.len(), 2);
        assert!(init.iter().all(|d| d.len() + 48 <= 1500));
        assert!(feed(&mut p.b, &init[0]).is_empty());
        let resp = feed(&mut p.b, &init[1]);
        assert_eq!(resp.len(), 2);
        assert!(feed(&mut p.a, &resp[0]).is_empty());
        assert_eq!(feed(&mut p.a, &resp[1]).len(), 1);
    }

    /// Segments arriving out of order still assemble
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_segments_out_of_order() {
        let mut p = static_auth_pair(1280, 1280);
        let init = initiation_datagrams(&mut p.a);
        assert_eq!(init.len(), 3);
        assert!(feed(&mut p.b, &init[0]).is_empty());
        assert!(feed(&mut p.b, &init[2]).is_empty());
        assert!(!feed(&mut p.b, &init[1]).is_empty());
    }

    /// Duplicate segments are dropped; reassembly slots are write-once
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_duplicate_segment_dropped() {
        let mut p = static_auth_pair(1280, 1280);
        let init = initiation_datagrams(&mut p.a);
        assert!(feed(&mut p.b, &init[0]).is_empty());
        assert!(feed(&mut p.b, &init[1]).is_empty());
        feed_expect_drop(&mut p.b, &init[1]);
        assert!(!feed(&mut p.b, &init[2]).is_empty());
    }

    /// Nothing is buffered before segment 0 authenticates: a segment with a
    /// forged tag, and a segment arriving before segment 0, are both dropped
    /// without leaving state behind. This is the property that keeps the
    /// design free of an attacker-influenceable reassembly buffer.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_forged_segment_buffers_nothing() {
        let mut p = static_auth_pair(1280, 1280);
        let init = initiation_datagrams(&mut p.a);

        // Segment 1 before segment 0
        feed_expect_drop(&mut p.b, &init[1]);

        // Segment 0 with a corrupted tag, mac1 restamped the way an
        // observe-and-inject attacker can
        let mut forged = init[0].clone();
        forged[PQ_SEG_HDR_SZ] ^= 0xff;
        restamp_mac1(&mut forged, &p.b_public);
        feed_expect_drop(&mut p.b, &forged);

        // The genuine exchange still works afterwards, so no state was left
        assert!(feed(&mut p.b, &init[0]).is_empty());
        assert!(feed(&mut p.b, &init[1]).is_empty());
        assert!(!feed(&mut p.b, &init[2]).is_empty());
    }

    /// Mutual authentication: a mismatched long-term ML-KEM key fails in
    /// either direction.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_wrong_peer_key_rejected() {
        use std::sync::Arc;

        // The responder holds the wrong encapsulation key for the initiator,
        // so its transcript diverges at the identity-binding hash
        let mut p = static_auth_pair(0, 0);
        p.b.set_pq_static_auth(Arc::clone(&p.b_mlkem), ek_of(&random_mlkem_secret()))
            .unwrap();
        let init = create_handshake_init(&mut p.a);
        feed_expect_drop(&mut p.b, &init);

        // The initiator encapsulates to the wrong responder key, so the
        // responder cannot recover the identity at all
        let mut p = static_auth_pair(0, 0);
        p.a.set_pq_static_auth(Arc::clone(&p.a_mlkem), ek_of(&random_mlkem_secret()))
            .unwrap();
        let init = create_handshake_init(&mut p.a);
        feed_expect_drop(&mut p.b, &init);
    }

    /// Tampering with either response ciphertext desynchronises the chain and
    /// fails key confirmation. ML-KEM uses implicit rejection, so a corrupted
    /// ciphertext yields a *different* shared secret rather than an error.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_tampered_response_ciphertexts_rejected() {
        for offset in [PQS_RESP_CT_E_OFF + 50, PQS_RESP_CT_S_OFF + 50] {
            let mut p = static_auth_pair(0, 0);
            let init = create_handshake_init(&mut p.a);
            let mut resp = create_handshake_response(&mut p.b, &init);
            resp[offset] ^= 0xff;
            feed_expect_drop(&mut p.a, &resp);
        }
    }

    /// KEM binding: a static-KEM ciphertext lifted from a concurrent
    /// handshake is rejected. Both encapsulation keys and every ciphertext go
    /// into the transcript, so a ciphertext cannot be moved between sessions
    /// even though ML-KEM itself is not MAL-BIND-K-PK.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_ciphertext_swap_between_handshakes_rejected() {
        let mut p = static_auth_pair(0, 0);
        let mut other = static_auth_pair(0, 0);

        let mut init = create_handshake_init(&mut p.a);
        let donor = create_handshake_init(&mut other.a);
        let ct = PQS_INIT_CT_S_OFF..PQS_INIT_ENC_STATIC_OFF;
        init[ct.clone()].copy_from_slice(&donor[ct]);
        restamp_mac1(&mut init, &p.b_public);
        feed_expect_drop(&mut p.b, &init);
    }

    /// Identity hiding: the identity field is unrecoverable without the
    /// responder's ML-KEM decapsulation key, and differs across handshakes to
    /// the same peer.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_identity_hidden_without_decapsulation_key() {
        use crate::noise::handshake::parse_pqs_handshake_anon;

        let mut p = static_auth_pair(0, 0);
        let first = create_handshake_init(&mut p.a);
        let second = {
            let mut dst = vec![0u8; 4096];
            match p.a.format_handshake_initiation(&mut dst, true) {
                TunnResult::WriteToNetwork(sent) => sent.to_vec(),
                other => panic!("unexpected {:?}", other),
            }
        };

        let ident = PQS_INIT_ENC_STATIC_OFF..PQS_INIT_ENC_TIMESTAMP_OFF;
        assert_ne!(first[ident.clone()], second[ident]);

        let parsed = match Tunn::parse_incoming_packet(&first).unwrap() {
            Packet::PqsHandshakeInit(pkt) => pkt,
            other => panic!("unexpected {:?}", other),
        };
        let hh = parse_pqs_handshake_anon(&p.b_mlkem, &p.b_public, &parsed)
            .expect("the responder recovers the initiator's identity");
        assert_eq!(hh.peer_static_public, *p.a_public.as_bytes());

        // An eavesdropper with the responder's X25519 key but not its ML-KEM
        // key learns nothing: identity confidentiality rests on ML-KEM alone
        assert!(parse_pqs_handshake_anon(&random_mlkem_secret(), &p.b_public, &parsed).is_err());
    }

    /// Device-level routing of a segmented static-auth initiation: segment 0
    /// resolves the peer, later segments do not.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_segment0_peer_lookup() {
        use crate::noise::handshake::parse_pqs_segment0_anon;

        let mut p = static_auth_pair(1280, 1280);

        fn chunk_of(dgram: &[u8]) -> &[u8] {
            &dgram[PQ_SEG_CHUNK_OFF..dgram.len() - PQ_SEG_MACS_SZ]
        }

        let init = initiation_datagrams(&mut p.a);
        assert_eq!(init.len(), 3);
        let hh = parse_pqs_segment0_anon(&p.b_mlkem, &p.b_public, chunk_of(&init[0]))
            .expect("segment 0 resolves the initiator");
        assert_eq!(hh.peer_static_public, *p.a_public.as_bytes());
        for seg in &init[1..] {
            assert!(parse_pqs_segment0_anon(&p.b_mlkem, &p.b_public, chunk_of(seg)).is_err());
        }

        // Response-direction segment 0 carries no identity field either
        let mut resp = vec![];
        for d in &init {
            resp.extend(feed(&mut p.b, d));
        }
        for seg in &resp {
            assert!(parse_pqs_segment0_anon(&p.b_mlkem, &p.b_public, chunk_of(seg)).is_err());
        }
    }

    /// No downgrade: a static-auth peer accepts nothing but types 8/9, and a
    /// peer without static auth accepts nothing that claims to be. Without
    /// this, an attacker who breaks X25519 could just send a type-1
    /// initiation and skip the post-quantum layer entirely.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_downgrade_rejected_in_both_directions() {
        let mut p = static_auth_pair(0, 0);
        let mut dst = vec![0u8; 4096];

        // Types 1 and 2, well-formed enough to parse
        for (msg_type, size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (PQ_HANDSHAKE_INIT, PQ_HANDSHAKE_INIT_SZ),
            (PQ_HANDSHAKE_RESP, PQ_HANDSHAKE_RESP_SZ),
        ] {
            let mut buf = vec![0u8; size];
            buf[0..4].copy_from_slice(&msg_type.to_le_bytes());
            let parsed = Tunn::parse_incoming_packet(&buf).unwrap();
            match p.b.handle_verified_packet(parsed, &mut dst) {
                TunnResult::Err(WireGuardError::WrongPacketType) => {}
                other => panic!("type {} must be rejected, got {:?}", msg_type, other),
            }
        }

        // ...and the converse: a type-8 initiation toward a peer that is not
        // configured for static auth
        let pqs_init = create_handshake_init(&mut p.a);
        let (_, mut plain) = create_two_tuns();
        match plain.handle_verified_packet(
            Tunn::parse_incoming_packet(&pqs_init).unwrap(),
            &mut dst,
        ) {
            TunnResult::Err(WireGuardError::WrongPacketType) => {}
            other => panic!("type 8 must be rejected by a phase-1 peer, got {:?}", other),
        }
    }

    /// The response type is guarded by the state machine rather than by a
    /// downstream AEAD failure: a phase-1 response cannot complete a
    /// static-auth initiation.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_wrong_response_type_rejected() {
        let mut p = static_auth_pair(0, 0);
        let _ = create_handshake_init(&mut p.a);

        // A genuine type-6 response from an unrelated exchange
        let (mut plain_a, mut plain_b) = create_two_tuns();
        let init = create_handshake_init(&mut plain_a);
        let pq_resp = create_handshake_response(&mut plain_b, &init);
        feed_expect_drop(&mut p.a, &pq_resp);

        // The static-auth exchange still completes normally afterwards
        // (force_resend, since the first initiation is still outstanding)
        let init = initiation_datagrams(&mut p.a).remove(0);
        let resp = create_handshake_response(&mut p.b, &init);
        let keepalive = parse_handshake_resp(&mut p.a, &resp);
        parse_keepalive(&mut p.b, &keepalive);
    }

    /// Config validation: static auth requires a path MTU of at least 1280,
    /// in whichever order the two are configured.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_path_mtu_floor_enforced() {
        use std::sync::Arc;

        let own = Arc::new(random_mlkem_secret());
        let peer = ek_of(&random_mlkem_secret());

        // MTU first, then the key
        let (mut a, _) = create_two_tuns();
        a.set_pq_path_mtu(576).unwrap();
        assert!(a.set_pq_static_auth(Arc::clone(&own), peer.clone()).is_err());
        assert!(!a.pq_static_auth_enabled());

        // Key first, then the MTU
        let (mut b, _) = create_two_tuns();
        b.set_pq_static_auth(Arc::clone(&own), peer).unwrap();
        assert!(b.pq_static_auth_enabled());
        assert!(b.set_pq_path_mtu(576).is_err());
        assert!(b.set_pq_path_mtu(1279).is_err());
        assert!(b.set_pq_path_mtu(1280).is_ok());
        // 0 keeps its meaning: never segment
        assert!(b.set_pq_path_mtu(0).is_ok());
    }

    /// Replay protection is unchanged: a repeated initiation is rejected on
    /// its timestamp.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_replayed_initiation_rejected() {
        let mut p = static_auth_pair(0, 0);
        let init = create_handshake_init(&mut p.a);
        assert!(!feed(&mut p.b, &init).is_empty());
        feed_expect_drop(&mut p.b, &init);
    }

    /// A truncated type-8 message retyped as a phase-1 or classical one must
    /// not decrypt: the three chains are domain-separated by construction
    /// constant, and the sizes do not line up either.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_truncate_retype_rejected() {
        let mut p = static_auth_pair(0, 0);
        let init = create_handshake_init(&mut p.a);

        let mut truncated = init[..PQ_HANDSHAKE_INIT_SZ].to_vec();
        truncated[0..4].copy_from_slice(&PQ_HANDSHAKE_INIT.to_le_bytes());
        restamp_mac1(&mut truncated, &p.b_public);
        feed_expect_drop(&mut p.b, &truncated);

        // ...and the genuine message still works, so nothing was consumed
        assert!(!feed(&mut p.b, &init).is_empty());
    }

    /// Types 8 and 9 are behind the same mac1 gate as every other handshake
    /// message. Without this the new types would be a cheaper way in than the
    /// ones they replace, which would be a DoS regression against vanilla
    /// WireGuard rather than the parity the design claims.
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_messages_are_mac1_gated() {
        use crate::noise::rate_limiter::RateLimiter;

        let mut p = static_auth_pair(0, 0);
        let mut cookie = vec![0u8; 4096];

        let init = create_handshake_init(&mut p.a);
        let resp = create_handshake_response(&mut p.b, &init);

        for (label, msg, receiver) in [
            ("type 8", init, p.b_public),
            ("type 9", resp, p.a_public),
        ] {
            let limiter = RateLimiter::new(&receiver, 100);
            // The genuine message passes
            assert!(
                limiter.verify_packet(None, &msg, &mut cookie).is_ok(),
                "{} with a valid mac1 must pass",
                label
            );
            // ...and one whose mac1 is wrong does not
            let mut forged = msg.clone();
            let mac1_off = forged.len() - 32;
            forged[mac1_off] ^= 0xff;
            match limiter.verify_packet(None, &forged, &mut cookie) {
                Err(TunnResult::Err(WireGuardError::InvalidMac)) => {}
                other => panic!("{} with a bad mac1 must be rejected, got {:?}", label, other),
            }
        }
    }

    /// A static-auth peer never emits phase-1 or classical messages
    #[test]
    #[cfg(feature = "pq")]
    fn pqs_peer_only_emits_type_8() {
        for mtu in [0u16, 1280, 1500] {
            let mut p = static_auth_pair(mtu, mtu);
            for dgram in initiation_datagrams(&mut p.a) {
                let msg_type = u32::from_le_bytes(dgram[0..4].try_into().unwrap());
                assert!(
                    msg_type == PQS_HANDSHAKE_INIT || msg_type == PQ_SEGMENT,
                    "unexpected outbound type {}",
                    msg_type
                );
            }
        }
    }
}
