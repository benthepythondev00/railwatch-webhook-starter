"""Verify RailWatch signed webhooks (X-RailWatch-Signature: sha256=<hex>).

RailWatch signs the exact raw request body with HMAC-SHA256 and the watch's
channel_secret. Verify the bytes you received, before any JSON parsing:
re-serialising parsed JSON changes the bytes (unicode escapes, 1799.0 vs 1799)
and the signature will no longer match.

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional

SIGNATURE_HEADER = "X-RailWatch-Signature"
DELIVERY_ID_HEADER = "X-RailWatch-Delivery-Id"


class InvalidSignature(Exception):
    """The body does not match the signature header for this secret."""


def compute_signature(secret: str, raw_body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not secret or not signature_header or not isinstance(raw_body, (bytes, bytearray)):
        return False
    expected = compute_signature(secret, bytes(raw_body))
    return hmac.compare_digest(expected, signature_header.strip())


def parse_verified(secret: str, raw_body: bytes, signature_header: Optional[str]) -> dict[str, Any]:
    """Return the decoded delivery envelope, or raise InvalidSignature."""
    if not verify_signature(secret, raw_body, signature_header):
        raise InvalidSignature("RailWatch signature mismatch")
    return json.loads(bytes(raw_body).decode("utf-8"))


class SeenDeliveries:
    """Small in-memory replay guard keyed on the signed envelope's delivery_id.

    The X-RailWatch-Delivery-Id header carries the same value but is not covered
    by the signature, so key on the body field after verification.

    Use a database unique key in production; this is enough for one process.
    """

    def __init__(self, limit: int = 10_000) -> None:
        self._seen: dict[str, None] = {}
        self._limit = limit

    def first_time(self, delivery_id: Optional[str]) -> bool:
        if not delivery_id:
            return True
        if delivery_id in self._seen:
            return False
        self._seen[delivery_id] = None
        if len(self._seen) > self._limit:
            self._seen.pop(next(iter(self._seen)))
        return True

    def forget(self, delivery_id: Optional[str]) -> None:
        if delivery_id:
            self._seen.pop(delivery_id, None)
