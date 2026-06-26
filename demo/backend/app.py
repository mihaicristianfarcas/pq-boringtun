"""FastAPI app for the PQ-WireGuard live demo.

Design note: this uses plain request/response (no WebSocket). For a one-shot
live demo, fewer moving parts is more reliable than streaming progress — the
connect/transfer POSTs return the full result and the page renders it; the
status indicators are polled.

Run (from repo root, inside the venv — see demo/README.md):

    # headline (VPS) mode
    DEMO_VPS_HOST=<vps-ip> python -m uvicorn app:app --app-dir demo/backend --port 8000

    # fallback (laptop-only) mode
    python demo/backend/app.py --local

Then open http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import os

from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import VARIANTS, Settings, Variant
from logfeed import read_events
from orchestrator import Orchestrator
from transfer import send_payload

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")


def _variant_or_404(key: str) -> Variant:
    v = VARIANTS.get(key)
    if v is None:
        raise HTTPException(status_code=404, detail=f"unknown variant: {key}")
    return v


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="PQ-WireGuard Demo", docs_url="/api/docs")
    orch = Orchestrator(settings)
    app.state.settings = settings
    app.state.orch = orch

    @app.get("/api/variants")
    def variants() -> dict:
        return {
            "mode": "local" if settings.local else "vps",
            "vps_host": settings.vps_host,
            "receiver_port": settings.receiver_port,
            "variants": [v.as_public_dict() for v in VARIANTS.values()],
        }

    @app.get("/api/status")
    def status() -> dict:
        return orch.status()

    @app.get("/api/logs/{variant}")
    def logs(variant: str, after: int = 0) -> dict:
        """New handshake-log events for the live strip, since cursor ``after``."""
        v = _variant_or_404(variant)
        events, cursor = read_events(settings.workdir, v.key, after)
        return {"variant": v.key, "events": events, "cursor": cursor}

    @app.post("/api/connect/{variant}")
    def connect(variant: str) -> dict:
        v = _variant_or_404(variant)
        return orch.connect_and_capture(v)

    @app.post("/api/transfer/{variant}")
    async def transfer(
        variant: str,
        file: UploadFile | None = None,
        text: str | None = Form(default=None),
    ) -> dict:
        v = _variant_or_404(variant)
        if file is not None:
            data = await file.read()
            filename = file.filename or "upload.bin"
            content_type = file.content_type or "application/octet-stream"
        elif text is not None:
            data = text.encode("utf-8")
            filename = "secret.txt"
            content_type = "text/plain"
        else:
            raise HTTPException(status_code=400, detail="provide a file or text")
        # send_payload is blocking (sync httpx); offload off the event loop.
        import anyio
        return await anyio.to_thread.run_sync(
            send_payload, settings, v, data, filename, content_type
        )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    # static assets (css/js) — mounted last so /api/* and / take precedence
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")

    return app


# module-level app for `uvicorn app:app`
app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="PQ-WireGuard live demo server")
    parser.add_argument("--local", action="store_true",
                        help="laptop-only fallback (loopback peer, no VPS)")
    parser.add_argument("--vps-host", default=os.environ.get("DEMO_VPS_HOST", ""),
                        help="public IP/host of the VPS peer")
    parser.add_argument("--egress-iface", default=os.environ.get("DEMO_EGRESS_IFACE", "en0"),
                        help="physical interface the handshake leaves by")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    settings = Settings(
        local=args.local,
        vps_host=args.vps_host,
        egress_iface=args.egress_iface,
    )
    import uvicorn
    uvicorn.run(create_app(settings), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
