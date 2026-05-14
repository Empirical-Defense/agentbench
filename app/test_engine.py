from __future__ import annotations

import logging
from typing import Tuple

import requests

from app.constants import API_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


def send_prompt(vendor_endpoint: str, prompt: str, timeout_seconds: int = API_TIMEOUT_SECONDS) -> Tuple[str, str]:
    """Send a prompt to vendor endpoint and extract response. Returns (response, status)."""
    try:
        response = requests.post(
            vendor_endpoint,
            json={"prompt": prompt},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        error_msg = f"API request failed ({exc.__class__.__name__})"
        logger.warning("Failed to send prompt: %s", error_msg)
        return "", error_msg

    payload: object
    try:
        payload = response.json()
    except ValueError:
        text_response = response.text.strip()
        if text_response:
            return text_response, "ok"
        logger.warning("API returned empty response")
        return "", "API returned non-JSON empty response"

    if isinstance(payload, dict):
        for key in ("response", "output", "text", "answer"):
            value = payload.get(key)
            if isinstance(value, str):
                return value, "ok"
        return str(payload), "ok"

    return str(payload), "ok"
