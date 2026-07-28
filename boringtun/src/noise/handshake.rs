// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{HandshakeInit, HandshakeResponse, PacketCookieReply};
#[cfg(feature = "pq")]
use super::{PqHandshakeInit, PqHandshakeResponse};
use crate::noise::errors::WireGuardError;
use crate::noise::session::Session;
#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;
use crate::x25519;
use aead::{Aead, Payload};
use blake2::digest::{FixedOutput, KeyInit};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::XChaCha20Poly1305;
use rand_core::OsRng;
#[cfg(feature = "pq")]
use ml_kem::{
    kem::Kem, Encapsulate, EncapsulationKey768, KeyExport, MlKem768,
    kem::TryDecapsulate,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::convert::TryInto;
use std::time::{Duration, SystemTime};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

// PQ transcripts are domain-separated from classical ones so that a truncated
// and retyped PQ init can never decrypt under the classical chain (and vice
// versa). The IDENTIFIER is unchanged; only the CONSTRUCTION differs:
// CONSTRUCTION_PQ = "Noise_IKpsk2_25519+MLKEM768_ChaChaPoly_BLAKE2s"
// (referenced by the pinning test that ties the constants below to their
// derivation)
#[cfg(feature = "pq")]
#[allow(dead_code)]
pub(crate) const CONSTRUCTION_PQ: &[u8] = b"Noise_IKpsk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";
#[cfg(feature = "pq")]
#[allow(dead_code)]
pub(crate) const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

// initiator.chaining_key = HASH(CONSTRUCTION_PQ)
#[cfg(feature = "pq")]
const INITIAL_CHAIN_KEY_PQ: [u8; KEY_LEN] = [
    92, 212, 118, 82, 10, 10, 246, 131, 71, 61, 77, 160, 151, 184, 203, 249, 86, 84, 163, 106, 11,
    2, 99, 179, 63, 208, 66, 103, 187, 164, 135, 172,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
#[cfg(feature = "pq")]
const INITIAL_CHAIN_HASH_PQ: [u8; KEY_LEN] = [
    230, 124, 28, 213, 149, 146, 162, 100, 240, 251, 122, 175, 64, 160, 57, 141, 94, 165, 206, 197,
    218, 229, 9, 122, 57, 38, 118, 2, 81, 247, 29, 235,
];

/// Label for deriving the per-handshake segment tag key off a chain value,
/// in the style of LABEL_MAC1/LABEL_COOKIE.
#[cfg(feature = "pq")]
pub(crate) const LABEL_SEG: &[u8; 8] = b"pq-seg--";

#[inline]
pub(crate) fn b2s_hash(data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(data1);
    hash.update(data2);
    hash.finalize().into()
}

#[inline]
/// RFC 2401 HMAC+Blake2s, not to be confused with *keyed* Blake2s
pub(crate) fn b2s_hmac(key: &[u8], data1: &[u8]) -> [u8; 32] {
    use blake2::digest::Update;
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    let mut hmac = HmacBlake2s::new_from_slice(key).unwrap();
    hmac.update(data1);
    hmac.finalize_fixed().into()
}

#[inline]
/// Like b2s_hmac, but chain data1 and data2 together
pub(crate) fn b2s_hmac2(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 32] {
    use blake2::digest::Update;
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    let mut hmac = HmacBlake2s::new_from_slice(key).unwrap();
    hmac.update(data1);
    hmac.update(data2);
    hmac.finalize_fixed().into()
}

#[inline]
pub(crate) fn b2s_keyed_mac_16(key: &[u8], data1: &[u8]) -> [u8; 16] {
    let mut hmac = Blake2sMac::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}

#[inline]
pub(crate) fn b2s_keyed_mac_16_2(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 16] {
    let mut hmac = Blake2sMac::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut hmac, data1);
    blake2::digest::Update::update(&mut hmac, data2);
    hmac.finalize_fixed().into()
}

pub(crate) fn b2s_mac_24(key: &[u8], data1: &[u8]) -> [u8; 24] {
    let mut hmac = Blake2sMac::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_chacha20_seal(ciphertext: &mut [u8], key: &[u8], counter: u64, data: &[u8], aad: &[u8]) {
    let mut nonce: [u8; 12] = [0; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    aead_chacha20_seal_inner(ciphertext, key, nonce, data, aad)
}

#[inline]
fn aead_chacha20_seal_inner(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
) {
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());

    ciphertext[..data.len()].copy_from_slice(data);

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext[..data.len()],
        )
        .unwrap();

    ciphertext[data.len()..].copy_from_slice(tag.as_ref());
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_chacha20_open(
    buffer: &mut [u8],
    key: &[u8],
    counter: u64,
    data: &[u8],
    aad: &[u8],
) -> Result<(), WireGuardError> {
    let mut nonce: [u8; 12] = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());

    aead_chacha20_open_inner(buffer, key, nonce, data, aad)
        .map_err(|_| WireGuardError::InvalidAeadTag)?;
    Ok(())
}

#[inline]
fn aead_chacha20_open_inner(
    buffer: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
) -> Result<(), ring::error::Unspecified> {
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());

    let mut inner_buffer = data.to_owned();

    let plaintext = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut inner_buffer,
    )?;

    buffer.copy_from_slice(plaintext);

    Ok(())
}

#[derive(Debug)]
/// This struct represents a 12 byte [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp
struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug)]
/// This struct computes a [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp from current system time
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    /// Create a new TimeStamper
    pub fn new() -> TimeStamper {
        TimeStamper {
            duration_at_start: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            instant_at_start: Instant::now(),
        }
    }

    /// Take time reading and generate a 12 byte timestamp
    pub fn stamp(&self) -> [u8; 12] {
        const TAI64_BASE: u64 = (1u64 << 62) + 37;
        let mut ext_stamp = [0u8; 12];
        let stamp = Instant::now().duration_since(self.instant_at_start) + self.duration_at_start;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + TAI64_BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

impl Tai64N {
    /// A zeroed out timestamp
    fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    /// Parse a timestamp from a 12 byte u8 slice
    fn parse(buf: &[u8; 12]) -> Result<Tai64N, WireGuardError> {
        if buf.len() < 12 {
            return Err(WireGuardError::InvalidTai64nTimestamp);
        }

        let (sec_bytes, nano_bytes) = buf.split_at(std::mem::size_of::<u64>());
        let secs = u64::from_be_bytes(sec_bytes.try_into().unwrap());
        let nano = u32::from_be_bytes(nano_bytes.try_into().unwrap());

        // WireGuard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(WireGuardError::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(WireGuardError::InvalidTai64nTimestamp);
        //}

        Ok(Tai64N { secs, nano })
    }

    /// Check if this timestamp represents a time that is chronologically after the time represented
    /// by the other timestamp
    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

/// Parameters used by the noise protocol
struct NoiseParams {
    /// Our static public key
    static_public: x25519::PublicKey,
    /// Our static private key
    static_private: x25519::StaticSecret,
    /// Static public key of the other party
    peer_static_public: x25519::PublicKey,
    /// A shared key = DH(static_private, peer_static_public)
    static_shared: x25519::SharedSecret,
    /// A pre-computation of HASH("mac1----", peer_static_public) for this peer
    sending_mac1_key: [u8; KEY_LEN],
    /// An optional preshared key
    preshared_key: Option<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("static_private", &"<redacted>")
            .field("peer_static_public", &self.peer_static_public)
            .field("static_shared", &"<redacted>")
            .field("sending_mac1_key", &self.sending_mac1_key)
            .field("preshared_key", &self.preshared_key)
            .finish()
    }
}

struct HandshakeInitSentState {
    local_index: u32,
    hash: [u8; KEY_LEN],
    chaining_key: [u8; KEY_LEN],
    ephemeral_private: x25519::ReusableSecret,
    time_sent: Instant,
    #[cfg(feature = "pq")]
    mlkem_decapsulation_key: Option<ml_kem::DecapsulationKey768>,
    /// Reassembly buffer for a segmented PQ response (allocated only after the
    /// classical part of the response's segment 0 authenticated).
    #[cfg(feature = "pq")]
    pq_partial_resp: Option<Box<PqPartialResp>>,
}

/// Partially reassembled segmented PQ handshake initiation (responder side).
/// Created only after the 116-byte classical prefix of segment 0 fully
/// authenticated the initiator and the segment tag verified.
#[cfg(feature = "pq")]
struct PqPartialInit {
    /// Routing id of this segmented exchange (the initiator's sender_idx)
    hs_id: u32,
    /// Chain value after the static-static mixing step (the tag-key anchor)
    chaining_key: [u8; KEY_LEN],
    /// Transcript hash after the encrypted_timestamp mix (before the ek mix)
    hash: [u8; KEY_LEN],
    peer_ephemeral_public: x25519::PublicKey,
    peer_index: u32,
    seg_tag_key: [u8; KEY_LEN],
    seg_cnt: u8,
    stride: usize,
    /// Bitmap of received segments (MAX 8 segments)
    filled: u16,
    /// Assembly buffer for the complete type-5 message
    buf: [u8; super::PQ_HANDSHAKE_INIT_SZ],
    created: Instant,
}

#[cfg(feature = "pq")]
impl std::fmt::Debug for PqPartialInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqPartialInit")
            .field("hs_id", &self.hs_id)
            .field("seg_cnt", &self.seg_cnt)
            .field("stride", &self.stride)
            .field("filled", &self.filled)
            .finish()
    }
}

/// Partially reassembled segmented PQ handshake response (initiator side).
/// Lives inside the InitSent state so its lifetime is bounded by it.
#[cfg(feature = "pq")]
struct PqPartialResp {
    /// Chain value after the se mixing step (the tag-key anchor)
    chaining_key: [u8; KEY_LEN],
    /// Transcript hash after the responder ephemeral mix
    hash: [u8; KEY_LEN],
    peer_index: u32,
    seg_tag_key: [u8; KEY_LEN],
    seg_cnt: u8,
    stride: usize,
    filled: u16,
    /// Assembly buffer for the complete type-6 message
    buf: [u8; super::PQ_HANDSHAKE_RESP_SZ],
}

/// Outcome of feeding one authenticated segment into the handshake
#[cfg(feature = "pq")]
pub(super) enum PqSegOutcome {
    /// Segment accepted and buffered; nothing to send
    Buffered,
    /// A full PQ init was assembled; caller should format the response
    InitComplete,
    /// A full PQ response was assembled and verified; session established
    RespComplete(Box<Session>),
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("chaining_key", &self.chaining_key)
            .field("ephemeral_private", &"<redacted>")
            .field("time_sent", &self.time_sent)
            .finish()
    }
}

#[derive(Debug)]
enum HandshakeState {
    /// No handshake in process
    None,
    /// We initiated the handshake
    InitSent(HandshakeInitSentState),
    /// Handshake initiated by peer
    InitReceived {
        hash: [u8; KEY_LEN],
        chaining_key: [u8; KEY_LEN],
        peer_ephemeral_public: x25519::PublicKey,
        peer_index: u32,
        #[cfg(feature = "pq")]
        mlkem_encapsulation_key: Option<Vec<u8>>,
        /// Stride of the segmented initiation this state was assembled from,
        /// if any; drives the responder's stride mirroring
        #[cfg(feature = "pq")]
        pq_observed_stride: Option<usize>,
    },
    /// A segmented PQ initiation is being reassembled (segment 0 authenticated)
    #[cfg(feature = "pq")]
    PqInitBuffering(Box<PqPartialInit>),
    /// Handshake was established too long ago (implies no handshake is in progress)
    Expired,
}

pub struct Handshake {
    params: NoiseParams,
    /// Index of the next session
    next_index: u32,
    /// Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    previous: HandshakeState,
    /// Current handshake state
    state: HandshakeState,
    cookies: Cookies,
    /// The timestamp of the last handshake we received
    last_handshake_timestamp: Tai64N,
    // TODO: make TimeStamper a singleton
    stamper: TimeStamper,
    pub(super) last_rtt: Option<u32>,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 16]>,
    index: u32,
    write_cookie: Option<[u8; 16]>,
}

#[derive(Debug)]
pub struct HalfHandshake {
    pub peer_index: u32,
    pub peer_static_public: [u8; 32],
}

pub fn parse_handshake_anon(
    static_private: &x25519::StaticSecret,
    static_public: &x25519::PublicKey,
    packet: &HandshakeInit,
) -> Result<HalfHandshake, WireGuardError> {
    let peer_index = packet.sender_idx;
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = static_private.diffie_hellman(&peer_ephemeral_public);
    let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_open(
        &mut peer_static_public,
        &key,
        0,
        packet.encrypted_static,
        &hash,
    )?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

impl NoiseParams {
    /// New noise params struct from our secret key, peers public key, and optional preshared key
    fn new(
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
    ) -> NoiseParams {
        let static_shared = static_private.diffie_hellman(&peer_static_public);

        let initial_sending_mac_key = b2s_hash(LABEL_MAC1, peer_static_public.as_bytes());

        NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key,
        }
    }

    /// Set a new private key
    fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
    ) {
        // Check that the public key indeed matches the private key
        let check_key = x25519::PublicKey::from(&static_private);
        assert_eq!(check_key.as_bytes(), static_public.as_bytes());

        self.static_private = static_private;
        self.static_public = static_public;

        self.static_shared = self.static_private.diffie_hellman(&self.peer_static_public);
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        peer_static_public: x25519::PublicKey,
        global_idx: u32,
        preshared_key: Option<[u8; 32]>,
    ) -> Handshake {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        );

        Handshake {
            params,
            next_index: global_idx,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(),
            cookies: Default::default(),
            last_rtt: None,
        }
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        !matches!(self.state, HandshakeState::None | HandshakeState::Expired)
    }

    pub(crate) fn timer(&self) -> Option<Instant> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState { time_sent, .. }) => Some(time_sent),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) fn has_cookie(&self) -> bool {
        self.cookies.write_cookie.is_some()
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index as u8;
        self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1));
        self.next_index
    }

    pub(crate) fn set_static_private(
        &mut self,
        private_key: x25519::StaticSecret,
        public_key: x25519::PublicKey,
    ) {
        self.params.set_static_private(private_key, public_key)
    }

    pub(super) fn receive_handshake_initialization<'a>(
        &mut self,
        packet: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.static_public.as_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(
            &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
            &[0x01],
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = self
            .params
            .static_private
            .diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

        let mut peer_static_public_decrypted = [0u8; KEY_LEN];
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_chacha20_open(
            &mut peer_static_public_decrypted,
            &key,
            0,
            packet.encrypted_static,
            &hash,
        )?;

        ring::constant_time::verify_slices_are_equal(
            self.params.peer_static_public.as_bytes(),
            &peer_static_public_decrypted,
        )
        .map_err(|_| WireGuardError::WrongKey)?;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_chacha20_open(&mut timestamp, &key, 0, packet.encrypted_timestamp, &hash)?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(WireGuardError::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, packet.encrypted_timestamp);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
                #[cfg(feature = "pq")]
                mlkem_encapsulation_key: None,
                #[cfg(feature = "pq")]
                pq_observed_stride: None,
            },
        );

        self.format_handshake_response(dst)
    }

    pub(super) fn receive_handshake_response(
        &mut self,
        packet: HandshakeResponse,
    ) -> Result<Session, WireGuardError> {
        // Check if there is a handshake awaiting a response and return the correct one
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.receiver_idx => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        // A classical (type 2) response can never complete a PQ initiation;
        // enforce this in the state machine instead of relying on the
        // downstream AEAD failure.
        #[cfg(feature = "pq")]
        if state.mlkem_decapsulation_key.is_some() {
            return Err(WireGuardError::WrongPacketType);
        }

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = state
            .ephemeral_private
            .diffie_hellman(&unencrypted_ephemeral);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &self
                .params
                .static_private
                .diffie_hellman(&unencrypted_ephemeral)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_open(&mut [], &key, 0, packet.encrypted_nothing, &hash)?;

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = b2s_hash(hash, buf[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(rtt_time.as_millis() as u32);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: PacketCookieReply,
    ) -> Result<(), WireGuardError> {
        let mac1 = match self.cookies.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(WireGuardError::UnexpectedPacket);
            }
        };

        let local_index = self.cookies.index;
        if packet.receiver_idx != local_index {
            return Err(WireGuardError::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = b2s_hash(LABEL_COOKIE, self.params.peer_static_public.as_bytes()); // TODO: pre-compute

        let payload = Payload {
            aad: &mac1[0..16],
            msg: packet.encrypted_cookie,
        };
        let plaintext = XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .decrypt(packet.nonce.into(), payload)
            .map_err(|_| WireGuardError::InvalidAeadTag)?;

        let cookie = plaintext
            .try_into()
            .map_err(|_| WireGuardError::InvalidPacket)?;
        self.cookies.write_cookie = Some(cookie);
        Ok(())
    }

    // Compute and append mac1 and mac2 to a handshake message
    fn append_mac1_and_mac2<'a>(
        &mut self,
        local_index: u32,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let mac1_off = dst.len() - 32;
        let mac2_off = dst.len() - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1 = b2s_keyed_mac_16(&self.params.sending_mac1_key, &dst[..mac1_off]);

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 16] = if let Some(cookie) = self.cookies.write_cookie {
            b2s_keyed_mac_16(&cookie, &dst[..mac2_off])
        } else {
            [0u8; 16]
        };

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
        Ok(dst)
    }

    pub(super) fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::HANDSHAKE_INIT_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_static, rest) = rest.split_at_mut(32 + 16);
        let (encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

        let local_index = self.inc_index();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_INIT.to_le_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&self.params.peer_static_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_chacha20_seal(
            encrypted_static,
            &key,
            0,
            self.params.static_public.as_bytes(),
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp();
        aead_chacha20_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, encrypted_timestamp);

        let time_now = Instant::now();
        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: time_now,
                #[cfg(feature = "pq")]
                mlkem_decapsulation_key: None,
                #[cfg(feature = "pq")]
                pq_partial_resp: None,
            }),
        );

        self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_INIT_SZ])
    }

    fn format_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        if dst.len() < super::HANDSHAKE_RESP_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let (mut chaining_key, mut hash, peer_ephemeral_public, peer_index) = match state {
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
                #[cfg(feature = "pq")]
                mlkem_encapsulation_key: _,
                #[cfg(feature = "pq")]
                pq_observed_stride: _,
            } => (chaining_key, hash, peer_ephemeral_public, peer_index),
            _ => {
                panic!("Unexpected attempt to call send_handshake_response");
            }
        };

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_nothing, _) = rest.split_at_mut(16);

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        let local_index = self.inc_index();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_RESP.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &ephemeral_private
                .diffie_hellman(&self.params.peer_static_public)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

        let dst = self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_RESP_SZ])?;

        Ok((dst, Session::new(local_index, peer_index, temp2, temp3)))
    }

    // PQ hybrid handshake methods

    #[cfg(feature = "pq")]
    pub(super) fn format_pq_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::PQ_HANDSHAKE_INIT_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_static, rest) = rest.split_at_mut(32 + 16);
        let (encrypted_timestamp, rest) = rest.split_at_mut(12 + 16);
        let (mlkem_ek_field, _) = rest.split_at_mut(super::MLKEM768_PK_SIZE);

        let local_index = self.inc_index();

        // Same X25519 steps as format_handshake_initiation, but on the
        // domain-separated PQ chain (CONSTRUCTION_PQ)
        let mut chaining_key = INITIAL_CHAIN_KEY_PQ;
        let mut hash = INITIAL_CHAIN_HASH_PQ;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        // msg.message_type = 5 (PQ Init)
        message_type.copy_from_slice(&super::PQ_HANDSHAKE_INIT.to_le_bytes());
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
        let ephemeral_shared = ephemeral_private.diffie_hellman(&self.params.peer_static_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        aead_chacha20_seal(
            encrypted_static,
            &key,
            0,
            self.params.static_public.as_bytes(),
            &hash,
        );
        hash = b2s_hash(&hash, encrypted_static);
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        let timestamp = self.stamper.stamp();
        aead_chacha20_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
        hash = b2s_hash(&hash, encrypted_timestamp);

        // ML-KEM-768 ephemeral keygen
        let mut rng = rand_core_pq::UnwrapErr(getrandom_pq::SysRng);
        let (dk, ek): (ml_kem::DecapsulationKey768, EncapsulationKey768) =
            MlKem768::generate_keypair_from_rng(&mut rng);
        let ek_bytes = ek.to_bytes();
        mlkem_ek_field.copy_from_slice(ek_bytes.as_slice());
        // Mix ML-KEM ek into hash (bind to transcript)
        hash = b2s_hash(&hash, mlkem_ek_field);

        let time_now = Instant::now();
        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: time_now,
                mlkem_decapsulation_key: Some(dk),
                pq_partial_resp: None,
            }),
        );

        self.append_mac1_and_mac2(local_index, &mut dst[..super::PQ_HANDSHAKE_INIT_SZ])
    }

    /// Run the X25519 steps over the 116-byte classical prefix of a PQ init
    /// (domain-separated chain). Authenticates the initiator and validates the
    /// timestamp against the replay window, but does NOT commit it — callers
    /// commit `last_handshake_timestamp` once the whole message (or segment 0)
    /// is authenticated.
    #[cfg(feature = "pq")]
    #[allow(clippy::type_complexity)]
    fn process_pq_init_prefix(
        &mut self,
        unencrypted_ephemeral: &[u8; 32],
        encrypted_static: &[u8],
        encrypted_timestamp: &[u8],
    ) -> Result<([u8; KEY_LEN], [u8; KEY_LEN], x25519::PublicKey, Tai64N), WireGuardError> {
        let mut chaining_key = INITIAL_CHAIN_KEY_PQ;
        let mut hash = INITIAL_CHAIN_HASH_PQ;
        hash = b2s_hash(&hash, self.params.static_public.as_bytes());
        let peer_ephemeral_public = x25519::PublicKey::from(*unencrypted_ephemeral);
        hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
        chaining_key = b2s_hmac(
            &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
            &[0x01],
        );
        let ephemeral_shared = self
            .params
            .static_private
            .diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

        let mut peer_static_public_decrypted = [0u8; KEY_LEN];
        aead_chacha20_open(
            &mut peer_static_public_decrypted,
            &key,
            0,
            encrypted_static,
            &hash,
        )?;

        ring::constant_time::verify_slices_are_equal(
            self.params.peer_static_public.as_bytes(),
            &peer_static_public_decrypted,
        )
        .map_err(|_| WireGuardError::WrongKey)?;

        hash = b2s_hash(&hash, encrypted_static);
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_chacha20_open(&mut timestamp, &key, 0, encrypted_timestamp, &hash)?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            return Err(WireGuardError::WrongTai64nTimestamp);
        }

        hash = b2s_hash(&hash, encrypted_timestamp);

        Ok((chaining_key, hash, peer_ephemeral_public, timestamp))
    }

    #[cfg(feature = "pq")]
    pub(super) fn receive_pq_handshake_initialization(
        &mut self,
        packet: PqHandshakeInit,
    ) -> Result<(), WireGuardError> {
        let peer_index = packet.sender_idx;
        let (chaining_key, mut hash, peer_ephemeral_public, timestamp) = self
            .process_pq_init_prefix(
                packet.unencrypted_ephemeral,
                packet.encrypted_static,
                packet.encrypted_timestamp,
            )?;
        self.last_handshake_timestamp = timestamp;

        // ML-KEM: read ek from packet, mix into hash
        hash = b2s_hash(&hash, packet.mlkem_ephemeral_public);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
                mlkem_encapsulation_key: Some(packet.mlkem_ephemeral_public.to_vec()),
                pq_observed_stride: None,
            },
        );

        Ok(())
    }

    /// Formats the PQ handshake response into `dst`. Besides the formatted
    /// message and session, returns the response-direction segment tag key
    /// (anchored at the chain value after the se mix) and the `hs_id` under
    /// which segments of this response would be routed (the initiator's
    /// sender index), for use by the segmentation layer.
    #[cfg(feature = "pq")]
    #[allow(clippy::type_complexity)]
    pub(super) fn format_pq_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session, [u8; KEY_LEN], u32), WireGuardError> {
        if dst.len() < super::PQ_HANDSHAKE_RESP_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let (mut chaining_key, mut hash, peer_ephemeral_public, peer_index, mlkem_ek_bytes) =
            match state {
                HandshakeState::InitReceived {
                    chaining_key,
                    hash,
                    peer_ephemeral_public,
                    peer_index,
                    mlkem_encapsulation_key,
                    pq_observed_stride: _,
                } => (
                    chaining_key,
                    hash,
                    peer_ephemeral_public,
                    peer_index,
                    mlkem_encapsulation_key
                        .expect("PQ response requires ML-KEM encapsulation key"),
                ),
                _ => {
                    panic!("Unexpected attempt to call format_pq_handshake_response");
                }
            };

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_nothing, rest) = rest.split_at_mut(16);
        let (mlkem_ct_field, _) = rest.split_at_mut(super::MLKEM768_CT_SIZE);

        // Same X25519 steps as format_handshake_response
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        let local_index = self.inc_index();
        message_type.copy_from_slice(&super::PQ_HANDSHAKE_RESP.to_le_bytes());
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        let temp = b2s_hmac(&chaining_key, unencrypted_ephemeral);
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let ephemeral_shared = ephemeral_private.diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let temp = b2s_hmac(
            &chaining_key,
            &ephemeral_private
                .diffie_hellman(&self.params.peer_static_public)
                .to_bytes(),
        );
        chaining_key = b2s_hmac(&temp, &[0x01]);

        // Response-direction segment tag key, anchored after the se mix —
        // the last chain value the initiator can reach from segment 0 alone
        let seg_tag_key = b2s_hmac(&chaining_key, LABEL_SEG);

        // ML-KEM-768 encapsulation
        let ek_array: &[u8; super::MLKEM768_PK_SIZE] = mlkem_ek_bytes
            .as_slice()
            .try_into()
            .expect("ML-KEM ek wrong size");
        let ek = EncapsulationKey768::new(ek_array.into())
            .map_err(|_| WireGuardError::InvalidPacket)?;
        let mut rng = rand_core_pq::UnwrapErr(getrandom_pq::SysRng);
        let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
        mlkem_ct_field.copy_from_slice(ct.as_slice());
        // Mix ML-KEM shared secret into chaining key
        let temp = b2s_hmac(&chaining_key, ss.as_slice());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // Mix ciphertext into hash (bind to transcript)
        hash = b2s_hash(&hash, mlkem_ct_field);

        // PSK mixing (unchanged)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        hash = b2s_hash(&hash, &temp2);
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        // Derive session keys
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

        let dst =
            self.append_mac1_and_mac2(local_index, &mut dst[..super::PQ_HANDSHAKE_RESP_SZ])?;

        Ok((
            dst,
            Session::new(local_index, peer_index, temp2, temp3),
            seg_tag_key,
            peer_index,
        ))
    }

    #[cfg(feature = "pq")]
    pub(super) fn receive_pq_handshake_response(
        &mut self,
        packet: PqHandshakeResponse,
    ) -> Result<Session, WireGuardError> {
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.receiver_idx => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
        let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
        let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        let ephemeral_shared = state
            .ephemeral_private
            .diffie_hellman(&unencrypted_ephemeral);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let temp = b2s_hmac(
            &chaining_key,
            &self
                .params
                .static_private
                .diffie_hellman(&unencrypted_ephemeral)
                .to_bytes(),
        );
        chaining_key = b2s_hmac(&temp, &[0x01]);

        // ML-KEM-768 decapsulation
        let dk = state
            .mlkem_decapsulation_key
            .as_ref()
            .ok_or(WireGuardError::InvalidPacket)?;
        let ct: &[u8; super::MLKEM768_CT_SIZE] = packet
            .mlkem_ciphertext
            .try_into()
            .map_err(|_| WireGuardError::InvalidPacket)?;
        let ss = dk
            .try_decapsulate(ct.into())
            .map_err(|_| WireGuardError::MlKemDecapsulationFailed)?;
        // Mix ML-KEM shared secret into chaining key
        let temp = b2s_hmac(&chaining_key, ss.as_slice());
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // Mix ciphertext into hash (bind to transcript)
        hash = b2s_hash(&hash, packet.mlkem_ciphertext);

        // PSK mixing (unchanged)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        hash = b2s_hash(&hash, &temp2);
        aead_chacha20_open(&mut [], &key, 0, packet.encrypted_nothing, &hash)?;

        // Derive session keys
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(rtt_time.as_millis() as u32);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }

    // ---- PQ handshake segmentation (message type 7) ----

    /// Feed one parsed type-7 segment into the handshake state machine.
    /// Every failure is a silent drop at the wire level; errors returned here
    /// are for local bookkeeping only and are never answered.
    #[cfg(feature = "pq")]
    pub(super) fn receive_pq_segment(
        &mut self,
        packet: &super::PqSegment,
    ) -> Result<PqSegOutcome, WireGuardError> {
        // Direction: segments of a response carry our own local_index (with
        // the device-assigned upper 24 bits) as hs_id and require an
        // outstanding PQ initiation; anything else is init-direction.
        let matches_init_sent = |s: &HandshakeState| {
            matches!(
                s,
                HandshakeState::InitSent(st)
                    if st.local_index == packet.hs_id && st.mlkem_decapsulation_key.is_some()
            )
        };
        if matches_init_sent(&self.state) || matches_init_sent(&self.previous) {
            self.receive_pq_resp_segment(packet)
        } else {
            self.receive_pq_init_segment(packet)
        }
    }

    /// Init-direction (responder side) segment processing per the
    /// authenticate-then-buffer rule: segment 0's classical prefix fully
    /// authenticates the initiator before a single byte is buffered; the rest
    /// are gated by the per-handshake segment tag.
    #[cfg(feature = "pq")]
    fn receive_pq_init_segment(
        &mut self,
        packet: &super::PqSegment,
    ) -> Result<PqSegOutcome, WireGuardError> {
        const TOTAL: usize = super::PQ_HANDSHAKE_INIT_SZ;
        if packet.seg_idx == 0 {
            let chunk = packet.chunk;
            let stride = chunk.len();
            let cnt = packet.seg_cnt as usize;
            // Segment 0 must carry the full classical prefix (plus leading ek
            // bytes), and the stride it fixes must assemble to exactly TOTAL
            if stride < super::PQ_INIT_PREFIX_SZ
                || stride * (cnt - 1) >= TOTAL
                || stride * cnt < TOTAL
            {
                return Err(WireGuardError::IncorrectPacketLength);
            }
            // The inner message must be a type-5 init whose sender_idx equals
            // the hs_id these segments are routed under
            let inner_type = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            if inner_type != super::PQ_HANDSHAKE_INIT {
                return Err(WireGuardError::WrongPacketType);
            }
            let sender_idx = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            if sender_idx != packet.hs_id {
                return Err(WireGuardError::WrongIndex);
            }
            let unencrypted_ephemeral: &[u8; 32] = (&chunk[8..40]).try_into().unwrap();

            let (chaining_key, hash, peer_ephemeral_public, timestamp) = self
                .process_pq_init_prefix(
                    unencrypted_ephemeral,
                    &chunk[40..88],
                    &chunk[88..super::PQ_INIT_PREFIX_SZ],
                )?;

            // Authenticate the segment itself (header fields + chunk) before
            // consuming the timestamp or committing any state
            let seg_tag_key = b2s_hmac(&chaining_key, LABEL_SEG);
            verify_pq_seg_tag(&seg_tag_key, packet)?;

            self.last_handshake_timestamp = timestamp;

            let mut partial = Box::new(PqPartialInit {
                hs_id: packet.hs_id,
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index: sender_idx,
                seg_tag_key,
                seg_cnt: packet.seg_cnt,
                stride,
                filled: 1,
                buf: [0u8; TOTAL],
                created: Instant::now(),
            });
            partial.buf[..stride].copy_from_slice(chunk);
            // Single slot, replaced by any newer authenticated segment 0
            self.previous =
                std::mem::replace(&mut self.state, HandshakeState::PqInitBuffering(partial));
            return Ok(PqSegOutcome::Buffered);
        }

        // Segments 1..n are only valid against a buffering slot for this hs_id
        let complete = {
            let partial = match &mut self.state {
                HandshakeState::PqInitBuffering(p) if p.hs_id == packet.hs_id => p,
                _ => return Err(WireGuardError::UnexpectedPacket),
            };
            pq_fill_segment(
                &mut partial.filled,
                partial.stride,
                partial.seg_cnt,
                &partial.seg_tag_key,
                TOTAL,
                &mut partial.buf,
                packet,
            )?
        };
        if !complete {
            return Ok(PqSegOutcome::Buffered);
        }

        // Assembly complete: resume at the ek-mixing step
        let partial = match std::mem::replace(&mut self.state, HandshakeState::None) {
            HandshakeState::PqInitBuffering(p) => p,
            _ => unreachable!(),
        };
        let ek = &partial.buf
            [super::PQ_INIT_PREFIX_SZ..super::PQ_INIT_PREFIX_SZ + super::MLKEM768_PK_SIZE];
        let hash = b2s_hash(&partial.hash, ek);
        self.state = HandshakeState::InitReceived {
            chaining_key: partial.chaining_key,
            hash,
            peer_ephemeral_public: partial.peer_ephemeral_public,
            peer_index: partial.peer_index,
            mlkem_encapsulation_key: Some(ek.to_vec()),
            pq_observed_stride: Some(partial.stride),
        };
        Ok(PqSegOutcome::InitComplete)
    }

    /// Response-direction (initiator side) segment processing. Segment 0 is
    /// authenticated via the classical chain (ee + se DHs anchor the tag key);
    /// the reassembly buffer lives inside the InitSent state so its lifetime
    /// is bounded by it.
    #[cfg(feature = "pq")]
    fn receive_pq_resp_segment(
        &mut self,
        packet: &super::PqSegment,
    ) -> Result<PqSegOutcome, WireGuardError> {
        const TOTAL: usize = super::PQ_HANDSHAKE_RESP_SZ;
        let (state, is_previous) = match (&mut self.state, &mut self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.hs_id => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.hs_id => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        if packet.seg_idx == 0 {
            let chunk = packet.chunk;
            let stride = chunk.len();
            let cnt = packet.seg_cnt as usize;
            if stride < super::PQ_RESP_PREFIX_SZ
                || stride * (cnt - 1) >= TOTAL
                || stride * cnt < TOTAL
            {
                return Err(WireGuardError::IncorrectPacketLength);
            }
            let inner_type = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            if inner_type != super::PQ_HANDSHAKE_RESP {
                return Err(WireGuardError::WrongPacketType);
            }
            let peer_index = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            let receiver_idx = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
            if receiver_idx != packet.hs_id {
                return Err(WireGuardError::WrongIndex);
            }
            let ephemeral_bytes: [u8; 32] = chunk[12..44].try_into().unwrap();
            let unencrypted_ephemeral = x25519::PublicKey::from(ephemeral_bytes);

            // Classical response steps (ee + se DHs) — the same cost profile
            // vanilla response processing already has, behind the mac1 gate
            let hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
            let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
            let mut chaining_key = b2s_hmac(&temp, &[0x01]);
            let ephemeral_shared = state
                .ephemeral_private
                .diffie_hellman(&unencrypted_ephemeral);
            let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
            chaining_key = b2s_hmac(&temp, &[0x01]);
            let temp = b2s_hmac(
                &chaining_key,
                &self
                    .params
                    .static_private
                    .diffie_hellman(&unencrypted_ephemeral)
                    .to_bytes(),
            );
            chaining_key = b2s_hmac(&temp, &[0x01]);

            let seg_tag_key = b2s_hmac(&chaining_key, LABEL_SEG);
            verify_pq_seg_tag(&seg_tag_key, packet)?;

            // Only after full segment-0 authentication: allocate the single
            // reassembly buffer, storing the intermediate chain values so
            // assembly does not redo the DHs
            let mut partial = Box::new(PqPartialResp {
                chaining_key,
                hash,
                peer_index,
                seg_tag_key,
                seg_cnt: packet.seg_cnt,
                stride,
                filled: 1,
                buf: [0u8; TOTAL],
            });
            partial.buf[..stride].copy_from_slice(chunk);
            state.pq_partial_resp = Some(partial);
            return Ok(PqSegOutcome::Buffered);
        }

        let complete = {
            let partial = state
                .pq_partial_resp
                .as_mut()
                .ok_or(WireGuardError::UnexpectedPacket)?;
            pq_fill_segment(
                &mut partial.filled,
                partial.stride,
                partial.seg_cnt,
                &partial.seg_tag_key,
                TOTAL,
                &mut partial.buf,
                packet,
            )?
        };
        if !complete {
            return Ok(PqSegOutcome::Buffered);
        }

        // Assembly complete: resume at the decapsulation step
        let partial = state.pq_partial_resp.take().unwrap();
        let ct: &[u8; super::MLKEM768_CT_SIZE] = (&partial.buf
            [super::PQ_RESP_PREFIX_SZ..super::PQ_RESP_PREFIX_SZ + super::MLKEM768_CT_SIZE])
            .try_into()
            .unwrap();
        let dk = state
            .mlkem_decapsulation_key
            .as_ref()
            .ok_or(WireGuardError::InvalidPacket)?;
        let ss = dk
            .try_decapsulate(ct.into())
            .map_err(|_| WireGuardError::MlKemDecapsulationFailed)?;
        // Mix ML-KEM shared secret into chaining key
        let temp = b2s_hmac(&partial.chaining_key, ss.as_slice());
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        // Mix ciphertext into hash (bind to transcript)
        let mut hash = b2s_hash(&partial.hash, ct);
        // PSK mixing (unchanged)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        hash = b2s_hash(&hash, &temp2);
        // encrypted_nothing provides explicit key confirmation over the full
        // transcript exactly as in the unsegmented path
        aead_chacha20_open(
            &mut [],
            &key,
            0,
            &partial.buf[44..super::PQ_RESP_PREFIX_SZ],
            &hash,
        )?;

        // Derive session keys
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

        let local_index = state.local_index;
        let peer_index = partial.peer_index;
        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(rtt_time.as_millis() as u32);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(PqSegOutcome::RespComplete(Box::new(Session::new(
            local_index,
            peer_index,
            temp3,
            temp2,
        ))))
    }

    /// Split a fully formatted PQ handshake message into type-7 segments,
    /// packed contiguously at fixed stride into `dst`. Returns
    /// (segment count, on-wire size of full segments, size of the last one).
    #[cfg(feature = "pq")]
    pub(super) fn segment_pq_message(
        &mut self,
        inner: &[u8],
        hs_id: u32,
        stride: usize,
        seg_tag_key: &[u8; KEY_LEN],
        dst: &mut [u8],
    ) -> Result<(usize, usize, usize), WireGuardError> {
        let total = inner.len();
        if stride == 0 {
            return Err(WireGuardError::InvalidParameter);
        }
        let count = total.div_ceil(stride);
        if count < super::PQ_MIN_SEG_CNT {
            return Err(WireGuardError::InvalidParameter);
        }
        if count > super::PQ_MAX_SEGMENTS {
            return Err(WireGuardError::TooManySegments);
        }
        let seg_size = super::PQ_SEG_OVERHEAD + stride;
        let last_chunk = total - stride * (count - 1);
        let last_size = super::PQ_SEG_OVERHEAD + last_chunk;
        if dst.len() < seg_size * (count - 1) + last_size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        for i in 0..count {
            let chunk_end = total.min((i + 1) * stride);
            let chunk = &inner[i * stride..chunk_end];
            let off = i * seg_size;
            let seg_len = super::PQ_SEG_OVERHEAD + chunk.len();
            let header = pq_seg_header(hs_id, i as u8, count as u8);
            let tag = b2s_keyed_mac_16_2(seg_tag_key, &header, chunk);
            let seg = &mut dst[off..off + seg_len];
            seg[..super::PQ_SEG_HDR_SZ].copy_from_slice(&header);
            seg[super::PQ_SEG_HDR_SZ..super::PQ_SEG_CHUNK_OFF].copy_from_slice(&tag);
            seg[super::PQ_SEG_CHUNK_OFF..super::PQ_SEG_CHUNK_OFF + chunk.len()]
                .copy_from_slice(chunk);
            // Standard cookie MACs per segment; hs_id doubles as the
            // sender_idx a cookie reply would reference
            self.append_mac1_and_mac2(hs_id, seg)?;
        }
        Ok((count, seg_size, last_size))
    }

    /// Segmentation parameters for the outstanding PQ initiation: its hs_id
    /// (our local index) and the init-direction segment tag key, anchored at
    /// the chain value after the static-static mix.
    #[cfg(feature = "pq")]
    pub(super) fn current_init_seg_params(&self) -> Option<(u32, [u8; KEY_LEN])> {
        match &self.state {
            HandshakeState::InitSent(s) if s.mlkem_decapsulation_key.is_some() => {
                Some((s.local_index, b2s_hmac(&s.chaining_key, LABEL_SEG)))
            }
            _ => None,
        }
    }

    /// Stride of the segmented initiation the current InitReceived state was
    /// assembled from, if any; drives responder stride mirroring.
    #[cfg(feature = "pq")]
    pub(super) fn pq_observed_stride(&self) -> Option<usize> {
        match &self.state {
            HandshakeState::InitReceived {
                pq_observed_stride, ..
            } => *pq_observed_stride,
            _ => None,
        }
    }

    /// Drop partially reassembled initiations older than REKEY_TIMEOUT; the
    /// initiator retransmits (as a fresh handshake) on that period anyway.
    #[cfg(feature = "pq")]
    pub(super) fn expire_pq_partial_init(&mut self) {
        use crate::noise::timers::REKEY_TIMEOUT;
        if let HandshakeState::PqInitBuffering(p) = &self.state {
            if p.created.elapsed() >= REKEY_TIMEOUT {
                self.state = HandshakeState::None;
            }
        }
        if let HandshakeState::PqInitBuffering(p) = &self.previous {
            if p.created.elapsed() >= REKEY_TIMEOUT {
                self.previous = HandshakeState::None;
            }
        }
    }
}

/// The 12 header bytes of a type-7 segment (covered by the segment tag)
#[cfg(feature = "pq")]
fn pq_seg_header(hs_id: u32, seg_idx: u8, seg_cnt: u8) -> [u8; super::PQ_SEG_HDR_SZ] {
    let mut header = [0u8; super::PQ_SEG_HDR_SZ];
    header[0..4].copy_from_slice(&super::PQ_SEGMENT.to_le_bytes());
    header[4..8].copy_from_slice(&hs_id.to_le_bytes());
    header[8] = seg_idx;
    header[9] = seg_cnt;
    header
}

#[cfg(feature = "pq")]
fn verify_pq_seg_tag(
    seg_tag_key: &[u8; KEY_LEN],
    packet: &super::PqSegment,
) -> Result<(), WireGuardError> {
    let header = pq_seg_header(packet.hs_id, packet.seg_idx, packet.seg_cnt);
    let tag = b2s_keyed_mac_16_2(seg_tag_key, &header, packet.chunk);
    ring::constant_time::verify_slices_are_equal(&tag, packet.tag)
        .map_err(|_| WireGuardError::InvalidMac)
}

/// Write-once fill of one non-zero segment into a reassembly buffer, after
/// validating count/stride/length rigidity and the segment tag.
/// Returns true when the assembly is complete.
#[cfg(feature = "pq")]
fn pq_fill_segment(
    filled: &mut u16,
    stride: usize,
    seg_cnt: u8,
    seg_tag_key: &[u8; KEY_LEN],
    total: usize,
    buf: &mut [u8],
    packet: &super::PqSegment,
) -> Result<bool, WireGuardError> {
    if packet.seg_cnt != seg_cnt {
        return Err(WireGuardError::InvalidPacket);
    }
    let idx = packet.seg_idx as usize;
    let cnt = seg_cnt as usize;
    let expected = if idx + 1 == cnt {
        total - stride * (cnt - 1)
    } else {
        stride
    };
    if packet.chunk.len() != expected {
        return Err(WireGuardError::IncorrectPacketLength);
    }
    if *filled & (1 << idx) != 0 {
        // Slots are write-once; duplicates are dropped
        return Err(WireGuardError::DuplicateCounter);
    }
    verify_pq_seg_tag(seg_tag_key, packet)?;
    let off = idx * stride;
    buf[off..off + expected].copy_from_slice(packet.chunk);
    *filled |= 1 << idx;
    Ok(*filled == (1u16 << cnt) - 1)
}

#[cfg(feature = "pq")]
pub fn parse_pq_handshake_anon(
    static_private: &x25519::StaticSecret,
    static_public: &x25519::PublicKey,
    packet: &PqHandshakeInit,
) -> Result<HalfHandshake, WireGuardError> {
    parse_pq_prefix_anon(
        static_private,
        static_public,
        packet.sender_idx,
        packet.unencrypted_ephemeral,
        packet.encrypted_static,
    )
}

/// Extract the initiator's static key from segment 0 of a segmented PQ init
/// (the chunk starts with the inner type-5 message's classical prefix). Used
/// by the device layer to route the segment to the right peer.
#[cfg(feature = "pq")]
pub fn parse_pq_segment0_anon(
    static_private: &x25519::StaticSecret,
    static_public: &x25519::PublicKey,
    chunk: &[u8],
) -> Result<HalfHandshake, WireGuardError> {
    if chunk.len() < super::PQ_INIT_PREFIX_SZ {
        return Err(WireGuardError::InvalidPacket);
    }
    let inner_type = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
    if inner_type != super::PQ_HANDSHAKE_INIT {
        return Err(WireGuardError::WrongPacketType);
    }
    let sender_idx = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
    let unencrypted_ephemeral: &[u8; 32] = (&chunk[8..40]).try_into().unwrap();
    parse_pq_prefix_anon(
        static_private,
        static_public,
        sender_idx,
        unencrypted_ephemeral,
        &chunk[40..88],
    )
}

/// The classical prefix of a PQ init is transcript-compatible only with the
/// domain-separated PQ chain; static key extraction runs on that chain.
#[cfg(feature = "pq")]
fn parse_pq_prefix_anon(
    static_private: &x25519::StaticSecret,
    static_public: &x25519::PublicKey,
    peer_index: u32,
    unencrypted_ephemeral: &[u8; 32],
    encrypted_static: &[u8],
) -> Result<HalfHandshake, WireGuardError> {
    let mut chaining_key = INITIAL_CHAIN_KEY_PQ;
    let mut hash = INITIAL_CHAIN_HASH_PQ;
    hash = b2s_hash(&hash, static_public.as_bytes());
    let peer_ephemeral_public = x25519::PublicKey::from(*unencrypted_ephemeral);
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    let ephemeral_shared = static_private.diffie_hellman(&peer_ephemeral_public);
    let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
    chaining_key = b2s_hmac(&temp, &[0x01]);
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    aead_chacha20_open(&mut peer_static_public, &key, 0, encrypted_static, &hash)?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_seal_rfc7530_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let mut buffer = vec![0; plaintext.len() + 16];

        aead_chacha20_seal_inner(&mut buffer, &key, nonce, plaintext, &aad);

        const EXPECTED_CIPHERTEXT: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        const EXPECTED_TAG: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        assert_eq!(buffer[..plaintext.len()], EXPECTED_CIPHERTEXT);
        assert_eq!(buffer[plaintext.len()..], EXPECTED_TAG);
    }

    /// Pins the domain-separated PQ chain constants to their derivation
    /// (test vectors for the thesis artifact and any formal-analysis work):
    /// INITIAL_CHAIN_KEY_PQ = BLAKE2s(CONSTRUCTION_PQ)
    /// INITIAL_CHAIN_HASH_PQ = BLAKE2s(INITIAL_CHAIN_KEY_PQ || IDENTIFIER)
    #[test]
    #[cfg(feature = "pq")]
    fn pq_chain_constants_match_construction() {
        let key = b2s_hash(CONSTRUCTION_PQ, &[]);
        assert_eq!(key, INITIAL_CHAIN_KEY_PQ);
        let hash = b2s_hash(&key, IDENTIFIER);
        assert_eq!(hash, INITIAL_CHAIN_HASH_PQ);
        // And they must differ from the classical chain (domain separation)
        assert_ne!(INITIAL_CHAIN_KEY_PQ, INITIAL_CHAIN_KEY);
        assert_ne!(INITIAL_CHAIN_HASH_PQ, INITIAL_CHAIN_HASH);
    }

    #[test]
    fn symmetric_chacha20_seal_open() {
        let aad: [u8; 32] = Default::default();
        let key: [u8; 32] = Default::default();
        let counter = 0;

        let mut encrypted_nothing: [u8; 16] = Default::default();

        aead_chacha20_seal(&mut encrypted_nothing, &key, counter, &[], &aad);

        eprintln!("encrypted_nothing: {:?}", encrypted_nothing);

        aead_chacha20_open(&mut [], &key, counter, &encrypted_nothing, &aad)
            .expect("Should open what we just sealed");
    }
}
