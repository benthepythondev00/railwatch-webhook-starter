"""Receive RailWatch signed webhooks, verify them, and post a compact summary to Discord.

    RAILWATCH_SECRET=... DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
        python python/discord_relay.py            # listens on :8787, POST /railwatch

Standard library only. Put it behind HTTPS (a reverse proxy or a tunnel) before
you paste its URL into RailWatch.
"""
from __future__ import annotations

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from railwatch_verify import SIGNATURE_HEADER, SeenDeliveries, verify_signature

MAX_BODY = 1_000_000
SEEN = SeenDeliveries()


def discord_message(envelope: dict[str, Any], limit: int = 10) -> dict[str, Any]:
    lines = [f"**{envelope.get('watch_name') or 'RailWatch'}**: {envelope.get('event_count') or 0} change(s)"]
    for ev in (envelope.get("events") or [])[:limit]:
        title = ev.get("title") or ev.get("identity") or "change"
        url = ev.get("url")
        head = f"[{title}](<{url}>)" if url else title
        lines.append(f"- `{ev.get('change_type') or 'change'}` {head}: {ev.get('summary') or ''}")
    return {"content": "\n".join(lines)[:1990], "allowed_mentions": {"parse": []}}


def post_json(url: str, payload: dict[str, Any]) -> int:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "railwatch-webhook-starter"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status


class Handler(BaseHTTPRequestHandler):
    secret = os.environ.get("RAILWATCH_SECRET", "")
    discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
    path_expected = os.environ.get("RELAY_PATH", "/railwatch")
    sender = staticmethod(post_json)

    def _reply(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != self.path_expected:
            return self._reply(404, "not found")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._reply(413, "bad length")
        raw = self.rfile.read(length)
        if not verify_signature(self.secret, raw, self.headers.get(SIGNATURE_HEADER)):
            return self._reply(401, "invalid signature")
        envelope = json.loads(raw.decode("utf-8"))
        # Key on the signed body's delivery_id: the X-RailWatch-Delivery-Id header is not signed.
        delivery_id = envelope.get("delivery_id")
        if not SEEN.first_time(delivery_id):
            return self._reply(200, "duplicate ignored")
        try:
            if self.discord_url:
                self.sender(self.discord_url, discord_message(envelope))
        except Exception:  # let RailWatch see a failure; allow a later redelivery through
            SEEN.forget(delivery_id)
            return self._reply(502, "relay failed")
        return self._reply(200, "ok")

    def log_message(self, fmt: str, *args: Any) -> None:
        print("relay:", fmt % args)


def main() -> None:
    if not Handler.secret:
        raise SystemExit("Set RAILWATCH_SECRET to the channel_secret you gave RailWatch.")
    port = int(os.environ.get("PORT", "8787"))
    print(f"listening on :{port}{Handler.path_expected}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
