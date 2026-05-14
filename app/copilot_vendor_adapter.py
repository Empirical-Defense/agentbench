from __future__ import annotations

import json
import os
from typing import Any

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class PromptRequest(BaseModel):
    prompt: str


def _extract_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.strip()

    if isinstance(payload, dict):
        for key in ("response", "output", "text", "answer", "message", "content"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        # OpenAI-style payload compatibility.
        output_text = payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = payload.get("output")
        if isinstance(output, list):
            chunks: list[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for piece in content:
                    if not isinstance(piece, dict):
                        continue
                    text = piece.get("text")
                    if isinstance(text, str) and text.strip():
                        chunks.append(text.strip())
            if chunks:
                return "\n".join(chunks)

        # Chat-completions style fallback.
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict):
                    text = message.get("content")
                    if isinstance(text, str) and text.strip():
                        return text.strip()

    return ""


def _extract_text_recursive(payload: Any) -> str:
    """Best-effort recursive text extraction for workflow-style JSON payloads."""
    direct = _extract_text(payload)
    if direct:
        return direct

    if isinstance(payload, dict):
        # Prefer common content-bearing keys first.
        for key in ("result", "message", "reply", "answer", "body", "output", "outputs", "data"):
            if key in payload:
                nested = _extract_text_recursive(payload[key])
                if nested:
                    return nested

        # Then scan all values.
        for value in payload.values():
            nested = _extract_text_recursive(value)
            if nested:
                return nested

    if isinstance(payload, list):
        for item in payload:
            nested = _extract_text_recursive(item)
            if nested:
                return nested

    return ""


def _build_upstream_payload(prompt: str) -> dict[str, Any]:
    request_mode = os.getenv("COPILOT_REQUEST_MODE", "prompt").strip().lower()

    if request_mode == "messages":
        return {
            "messages": [{"role": "user", "content": prompt}],
        }

    request_field = os.getenv("COPILOT_REQUEST_FIELD", "prompt").strip() or "prompt"
    return {request_field: prompt}


app = FastAPI(title="AgentBench Copilot Vendor Adapter", version="0.1.0")


def _resolve_upstream_url() -> str | None:
    """Resolve the upstream agent/workflow URL, keeping the legacy Copilot name supported."""
    return os.getenv("UPSTREAM_AGENT_URL") or os.getenv("COPILOT_AGENT_URL")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/infer")
def infer(payload: PromptRequest) -> dict[str, str]:
    upstream_url = _resolve_upstream_url()
    if not upstream_url:
        raise HTTPException(status_code=500, detail="UPSTREAM_AGENT_URL or COPILOT_AGENT_URL is not set")

    timeout_seconds = int(os.getenv("COPILOT_TIMEOUT_SECONDS", "60"))

    headers: dict[str, str] = {"Content-Type": "application/json"}
    auth_type = os.getenv("COPILOT_AUTH_TYPE", "none").strip().lower()
    auth_value = os.getenv("COPILOT_AUTH_VALUE", "")

    if auth_type == "bearer" and auth_value:
        headers["Authorization"] = f"Bearer {auth_value}"
    elif auth_type == "token" and auth_value:
        headers["Authorization"] = auth_value

    try:
        response = requests.post(
            upstream_url,
            headers=headers,
            json=_build_upstream_payload(payload.prompt),
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Upstream Copilot agent request failed ({exc.__class__.__name__})",
        ) from exc

    try:
        data: Any = response.json()
    except ValueError:
        text = response.text.strip()
        if text:
            return {"response": text}
        raise HTTPException(status_code=502, detail="Upstream returned empty non-JSON response")

    text = _extract_text_recursive(data)
    if not text:
        # Do not fail hard for unknown-but-valid JSON schemas; return compact JSON text.
        return {"response": json.dumps(data, ensure_ascii=True)}

    return {"response": text}
