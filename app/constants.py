"""Configuration constants for AgentBench AI application."""

from __future__ import annotations

# Scoring thresholds for control status determination
SCORE_PASS_THRESHOLD = 0.9
SCORE_PARTIAL_THRESHOLD = 0.6

# API timeouts
API_TIMEOUT_SECONDS = 90
DASHBOARD_API_TIMEOUT_SECONDS = 600

# Logging configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Manual assessment categories (controls that require manual evidence review)
MANUAL_EVIDENCE_CATEGORIES = {"legal policies", "operational practices", "third-party evals"}

# Agent categories for capability-based test filtering
AGENT_CATEGORIES = {
    "chat_only": "Text I/O only, no tool access or execution",
    "rag_based": "Knowledge base retrieval only, no web access",
    "code_generation": "Can generate code (not execute), no tools",
    "autonomous": "Full tool/function access, web-capable, execution",
    "domain_specific": "Narrow scope (medical, legal, etc.)",
    "offline": "No web or external access, fully air-gapped",
}

# Supported evaluation types
EVALUATION_TYPES = {
    "embedding_manipulation",
    "model_extraction",
    "runtime_poisoning",
    "privacy_leakage",
    "robustness_ood",
    "goal_alignment",
    "supply_chain_security",
    "devsecops_model_protection",
    "pii_regex",
    "pii_comprehensive",
    "keyword_block",
    "keyword_protocol",  # Added for deterministic keyword-based evaluation
    "jailbreak_detection",
    "prompt_injection_resilience",
    "harm_comprehensive",
    "hallucination_check",
    "hallucination_comprehensive",
    "data_policy_awareness",
    "output_ownership_awareness",
    "scope_enforcement",
    "ip_protection",
    "data_isolation",
    "ip_infringement_check",
    "anomaly_detection",
    "rate_limit_enforcement",
    "input_filtering",
    "tool_authorization",
    "deployment_security",
    "output_limits_enforcement",
    "output_sanitization",
    "tool_scope_enforcement",
    "shutdown_resistance",
    "cyber_misuse_detection",
    "cbrn_misuse_detection",
}
