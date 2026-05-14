from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query

from app.config_loader import group_controls_by_category, load_controls
from app.constants import AGENT_CATEGORIES, LOG_FORMAT, LOG_LEVEL
from app.database import init_db
from app.models import AssessmentRequest, AssessmentResponse
from app.orchestrator import ComplianceOrchestrator
from app.prompt_configs import get_prompts_for_agent
from app.utils import collect_failed_tests, summarize_coverage, summarize_statuses

# Configure logging
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler for FastAPI startup/shutdown."""
    try:
        init_db()
        logger.info("Application startup complete")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    yield

app = FastAPI(title="AgentBench AI - AIUC Compliance Orchestrator", version="0.1.0", lifespan=lifespan)


def _validate_url(url: str) -> bool:
    """Validate that a string is a properly formatted URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def _env(name: str, default: str) -> str:
    """Read an AgentBench env var with default fallback."""
    value = os.getenv(name)
    if value is None:
        return default
    return value


def _resolve_agent_category(request_category: str | None) -> str:
    """Resolve agent category using request override then env fallback."""
    fallback = _env("AGENTBENCH_AGENT_CATEGORY", "chat_only").strip() or "chat_only"
    category = (request_category or fallback).strip()
    if category not in AGENT_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"agent_category must be one of {sorted(AGENT_CATEGORIES.keys())}; "
                f"received '{category}'"
            ),
        )
    return category


def _resolve_verification_agent_enabled(request_value: bool | None) -> bool:
    """Resolve verification-agent enablement; defaults to disabled unless explicitly configured."""
    if request_value is not None:
        return bool(request_value)
    env_value = (_env("AGENTBENCH_ENABLE_VERIFICATION_AGENT", "false") or "false").strip().lower()
    return env_value in {"1", "true", "yes", "on"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/controls")
def list_controls() -> dict[str, object]:
    """Retrieve all controls grouped by category."""
    controls = load_controls()
    grouped = group_controls_by_category(controls)
    return {
        "total_controls": len(controls),
        "categories": {
            category: [control.model_dump() for control in category_controls]
            for category, category_controls in grouped.items()
        },
    }


@app.get("/coverage")
def coverage_preview(
    include_optional: bool = True,
    control_ids: list[str] | None = Query(default=None),
    agent_category: str | None = Query(default=None),
) -> dict[str, object]:
    """Preview assessment coverage for selected controls."""
    controls = load_controls()
    resolved_category = _resolve_agent_category(agent_category)
    orchestrator = ComplianceOrchestrator(vendor_endpoint="", agent_category=resolved_category)

    preview: list[dict[str, object]] = []
    for control in controls:
        if not orchestrator._should_include(control, include_optional, control_ids):
            continue

        definition, definition_key = orchestrator._get_test_definition_for_control(control)

        if not orchestrator._is_definition_applicable_to_agent(definition):
            preview.append(
                {
                    "control_id": control.control_id,
                    "category": control.category,
                    "classification": "SKIPPED_AGENT_CATEGORY",
                    "reason": f"Not applicable to {resolved_category} agent",
                    "tested_by_definition": definition_key,
                    "evaluation_type": definition["evaluation"],
                    "prompt_count": len(get_prompts_for_agent(definition, resolved_category, control.control_id)),
                }
            )
            continue

        preview.append(
            {
                "control_id": control.control_id,
                "category": control.category,
                "classification": "AUTOMATED",
                "reason": "Will be evaluated by prompt-response tests",
                "tested_by_definition": definition_key,
                "evaluation_type": definition["evaluation"],
                "prompt_count": len(get_prompts_for_agent(definition, resolved_category, control.control_id)),
            }
        )

    coverage_counts = {
        "AUTOMATED": sum(1 for item in preview if item["classification"] == "AUTOMATED"),
        "MANUAL_EVIDENCE": sum(1 for item in preview if item["classification"] == "MANUAL_EVIDENCE"),
        "MISSING_AUTOMATION": sum(1 for item in preview if item["classification"] == "MISSING_AUTOMATION"),
        "SKIPPED_AGENT_CATEGORY": sum(1 for item in preview if item["classification"] == "SKIPPED_AGENT_CATEGORY"),
    }

    return {
        "agent_category": resolved_category,
        "total_controls_in_scope": len(preview),
        "counts": coverage_counts,
        "controls": preview,
    }


@app.post("/assess", response_model=AssessmentResponse)
def assess(payload: AssessmentRequest) -> AssessmentResponse:
    """Execute compliance assessment for a vendor endpoint."""
    if not payload.vendor_endpoint:
        raise HTTPException(status_code=400, detail="vendor_endpoint is required")
    
    if not _validate_url(payload.vendor_endpoint):
        raise HTTPException(
            status_code=400,
            detail="vendor_endpoint must be a valid HTTP/HTTPS URL"
        )

    resolved_category = _resolve_agent_category(payload.agent_category)
    verification_enabled = _resolve_verification_agent_enabled(payload.use_verification_agent)
    logger.info(
        "Starting assessment (agent_category=%s, verification_agent=%s)",
        resolved_category,
        verification_enabled,
    )
    try:
        orchestrator = ComplianceOrchestrator(
            vendor_endpoint=payload.vendor_endpoint,
            agent_category=resolved_category,
            allow_sensitive_probes=payload.allow_sensitive_probes,
            use_verification_agent=verification_enabled,
        )
        summary = orchestrator.run(
            include_optional=payload.include_optional,
            control_ids=payload.control_ids,
        )
        logger.info("Assessment completed")

        return AssessmentResponse(
            summary=summary,
            controls_by_status=summarize_statuses(summary.control_results),
            failed_tests=collect_failed_tests(summary.control_results),
            coverage=summarize_coverage(summary.control_results),
        )
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")
