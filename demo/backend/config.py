"""Variant registry and runtime settings for the PQ-WireGuard live demo.

Three WireGuard variants are demonstrated. Everything the UI shows is derived
from this registry, so the on-screen facts stay consistent with the thesis.

Two runtime modes:
  * "vps"   — tunnels go to a remote free-tier VPS (the headline demo).
  * "local" — both peers run on this Mac over loopback (the bullet-proof
              fallback for an unstable defense-room network). Selected with
              ``--local`` / ``DEMO_LOCAL=1``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# --- thesis reference numbers (Apple M4, Criterion crypto-only) ---------------
# Shown next to the live, RTT-inclusive handshake time to make the point that
# the microseconds of ML-KEM are invisible once a real network is involved.
THESIS_HANDSHAKE_US = {
    "vanilla": 150.8,
    "psk": 151.0,
    "pq": 247.3,
}


@dataclass(frozen=True)
class Variant:
    """One demonstrated configuration.

    ``init_size`` / ``resp_size`` are the *expected* on-the-wire handshake
    sizes from the thesis; the demo captures the real sizes live and should
    match these. They double as the fallback values if a live capture misses.
    """

    key: str                 # stable id used in URLs / WS messages
    label: str               # human label for the UI tab
    iface: str               # local boringtun interface (Mac side)
    peer_iface: str          # loopback peer interface (only used in --local)
    port: int                # UDP listen port (Mac side; VPS responder uses same)
    local_peer_port: int     # loopback peer's listen port (--local mode only)
    subnet: str              # tunnel /24
    mac_ip: str              # Mac tunnel address
    peer_ip: str             # peer (VPS / loopback) tunnel address
    build: str               # which boringtun binary: "vanilla" | "pq"
    uses_psk: bool           # configure an ML-KEM-derived preshared-key?
    init_size: int           # expected handshake init size (bytes)
    resp_size: int           # expected handshake response size (bytes)
    crypto: str              # short description of the key exchange
    quantum_safe: bool       # confidentiality safe against a quantum adversary?
    pq_forward_secrecy: bool # per-session PQ forward secrecy?
    note: str                # one-line nuance for the verdict panel

    @property
    def thesis_us(self) -> float:
        return THESIS_HANDSHAKE_US[self.key]

    def endpoint(self, settings: "Settings") -> str:
        """Where the Mac points its peer endpoint, ``host:port``.

        VPS mode: the responder is a *different host* listening on the same
        port number as the Mac. Local mode: the responder is a loopback peer on
        *this host*, so it must use a different port.
        """
        if settings.local:
            return f"127.0.0.1:{self.local_peer_port}"
        host = settings.vps_host or "127.0.0.1"
        return f"{host}:{self.port}"

    def as_public_dict(self) -> dict:
        """Everything the frontend needs to render this variant."""
        return {
            "key": self.key,
            "label": self.label,
            "expected_init": self.init_size,
            "expected_resp": self.resp_size,
            "crypto": self.crypto,
            "quantum_safe": self.quantum_safe,
            "pq_forward_secrecy": self.pq_forward_secrecy,
            "note": self.note,
            "thesis_us": self.thesis_us,
            # tunnel IP of the receiver — the "Open receiver view" link points here
            # so the arrivals page itself loads *through* this tunnel.
            "peer_ip": self.peer_ip,
        }


# Largest handshake across variants — used by the UI to scale the size bars
# consistently (so PQ visibly dwarfs vanilla).
MAX_HANDSHAKE_SIZE = 1332


VARIANTS: dict[str, Variant] = {
    "vanilla": Variant(
        key="vanilla",
        label="Vanilla",
        iface="utun20",
        peer_iface="utun30",
        port=51820,
        local_peer_port=51830,
        subnet="10.13.0.0/24",
        mac_ip="10.13.0.1",
        peer_ip="10.13.0.2",
        build="vanilla",
        uses_psk=False,
        init_size=148,
        resp_size=92,
        crypto="X25519 only",
        quantum_safe=False,
        pq_forward_secrecy=False,
        note="Key exchange is classical X25519 — recoverable by a future "
             "quantum adversary (harvest-now, decrypt-later).",
    ),
    "psk": Variant(
        key="psk",
        label="PSK-slot",
        iface="utun21",
        peer_iface="utun31",
        port=51821,
        local_peer_port=51831,
        subnet="10.13.1.0/24",
        mac_ip="10.13.1.1",
        peer_ip="10.13.1.2",
        build="vanilla",
        uses_psk=True,
        init_size=148,
        resp_size=92,
        crypto="X25519 + static ML-KEM PSK",
        quantum_safe=True,
        pq_forward_secrecy=False,
        note="Same wire size as vanilla, but the key mixes a one-time "
             "ML-KEM secret. Static PSK → no per-session PQ forward secrecy.",
    ),
    "pq": Variant(
        key="pq",
        label="PQ-hybrid",
        iface="utun22",
        peer_iface="utun32",
        port=51822,
        local_peer_port=51832,
        subnet="10.13.2.0/24",
        mac_ip="10.13.2.1",
        peer_ip="10.13.2.2",
        build="pq",
        uses_psk=False,
        init_size=1332,
        resp_size=1180,
        crypto="X25519 + ML-KEM-768 (fresh per session)",
        quantum_safe=True,
        pq_forward_secrecy=True,
        note="ML-KEM ek (msg 1) + ct (msg 2) ride the existing two messages. "
             "Fresh keypair each session → post-quantum forward secrecy.",
    ),
}


@dataclass
class Settings:
    """Runtime configuration, resolved from CLI flags / environment."""

    local: bool = field(
        default_factory=lambda: os.environ.get("DEMO_LOCAL", "") not in ("", "0")
    )
    # Public endpoint of the VPS (ignored in --local mode).
    vps_host: str = field(default_factory=lambda: os.environ.get("DEMO_VPS_HOST", ""))
    # Physical egress interface the handshake leaves by (for tcpdump).
    egress_iface: str = field(
        default_factory=lambda: os.environ.get("DEMO_EGRESS_IFACE", "en0")
    )
    # Directory holding the copied boringtun binaries + key material.
    workdir: str = field(
        default_factory=lambda: os.environ.get("DEMO_WORKDIR", "/tmp/pq-demo")
    )
    # Port the VPS-side receiver listens on (inside the tunnel).
    receiver_port: int = field(
        default_factory=lambda: int(os.environ.get("DEMO_RECEIVER_PORT", "8765"))
    )
    # Run privileged commands (tcpdump / wg / ifconfig) under sudo.
    use_sudo: bool = field(
        default_factory=lambda: os.environ.get("DEMO_NO_SUDO", "") in ("", "0")
    )

    @property
    def capture_iface(self) -> str:
        """tcpdump listens on loopback in local mode, egress otherwise."""
        return "lo0" if self.local else self.egress_iface
