"""Send a payload *through* the selected tunnel and verify it arrived intact.

The VPS receiver (demo/vps/receiver.py) listens on the tunnel IP, hashes what
it gets, and echoes the bytes back. A SHA-256 match proves the payload
traversed the encrypted tunnel and arrived byte-for-byte on the remote machine
— without needing a second screen on the VPS.
"""

from __future__ import annotations

import hashlib
import time

import httpx

from config import Settings, Variant


def send_payload(
    settings: Settings,
    v: Variant,
    data: bytes,
    filename: str,
    content_type: str,
) -> dict:
    """POST ``data`` to the receiver over the tunnel; verify the echo."""
    local_sha = hashlib.sha256(data).hexdigest()
    url = f"http://{v.peer_ip}:{settings.receiver_port}/payload"

    start = time.monotonic()
    try:
        resp = httpx.post(
            url,
            content=data,
            headers={
                "Content-Type": content_type,
                "X-Filename": filename,
            },
            timeout=15.0,
        )
        rtt_ms = round((time.monotonic() - start) * 1000.0, 1)
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "error": f"transfer failed over tunnel: {exc}",
            "variant": v.key,
        }

    if resp.status_code != 200:
        return {
            "ok": False,
            "error": f"receiver returned HTTP {resp.status_code}",
            "variant": v.key,
        }

    echoed = resp.content
    remote_sha = resp.headers.get("X-Sha256", "")
    echo_sha = hashlib.sha256(echoed).hexdigest()

    return {
        "ok": True,
        "variant": v.key,
        "bytes": len(data),
        "rtt_ms": rtt_ms,
        "local_sha256": local_sha,
        "remote_sha256": remote_sha,
        # The committee-facing claim: the remote machine received identical bytes.
        "vps_confirmed_identical": (remote_sha == local_sha and echo_sha == local_sha),
        "content_type": content_type,
        "filename": filename,
        # echoed bytes returned to the UI as a data URL for images
        "echo_b64": _maybe_b64(echoed, content_type),
    }


def _maybe_b64(data: bytes, content_type: str) -> str | None:
    """Base64 the echoed bytes for images so the UI can render the round-trip."""
    if content_type.startswith("image/"):
        import base64
        return base64.b64encode(data).decode("ascii")
    return None
