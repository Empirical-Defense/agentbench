from __future__ import annotations

import os
from unittest.mock import Mock, patch

from app.llm_evaluator import evaluate_with_llm


def test_llm_evaluator_openai_compatible_parses_json_result() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "openai_compatible",
            "AEGIS_LLM_EVALUATOR_OPENAI_API_KEY": "test-key",
            "AEGIS_LLM_EVALUATOR_OPENAI_BASE_URL": "https://api.openai.com/v1",
            "AEGIS_LLM_EVALUATOR_OPENAI_MODEL": "gpt-4.1-mini",
            "AEGIS_LLM_EVALUATOR_REDACT_SENSITIVE": "false",
        },
        clear=False,
    ), patch("app.llm_evaluator.requests.post") as mock_post:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"result":"PASS","reason":"Looks compliant"}'
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        result = evaluate_with_llm("hallucination_comprehensive", "prompt", "response")

    assert result == ("PASS", "Looks compliant")


def test_llm_evaluator_openai_compatible_requires_api_key() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "openai_compatible",
            "AEGIS_LLM_EVALUATOR_OPENAI_API_KEY": "",
        },
        clear=False,
    ):
        result = evaluate_with_llm("pii_regex", "prompt", "response")

    assert result is None


def test_llm_evaluator_custom_endpoint_still_supported() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "custom_endpoint",
            "AEGIS_LLM_EVALUATOR_ENDPOINT": "https://example.com/evaluate",
            "AEGIS_LLM_EVALUATOR_REDACT_SENSITIVE": "false",
        },
        clear=False,
    ), patch("app.llm_evaluator.requests.post") as mock_post:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "response": '{"result":"FAIL","reason":"Detected issue"}'
        }
        mock_post.return_value = mock_response

        result = evaluate_with_llm("pii_regex", "prompt", "response")

    assert result == ("FAIL", "Detected issue")


def test_llm_evaluator_azure_openai_parses_json_result() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "azure_openai",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_API_KEY": "azure-key",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_ENDPOINT": "https://my-aoai.openai.azure.com",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_DEPLOYMENT": "gpt-4o-mini",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_API_VERSION": "2024-06-01",
            "AEGIS_LLM_EVALUATOR_REDACT_SENSITIVE": "false",
        },
        clear=False,
    ), patch("app.llm_evaluator.requests.post") as mock_post:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"result":"PASS","reason":"Azure verdict"}'
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        result = evaluate_with_llm("hallucination_comprehensive", "prompt", "response")

    assert result == ("PASS", "Azure verdict")


def test_llm_evaluator_azure_openai_requires_endpoint_and_deployment() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "azure_openai",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_API_KEY": "azure-key",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_ENDPOINT": "",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_DEPLOYMENT": "",
        },
        clear=False,
    ):
        result = evaluate_with_llm("pii_regex", "prompt", "response")

    assert result is None


def test_llm_evaluator_azure_openai_bearer_token_auth() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "azure_openai",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_AUTH_MODE": "bearer_token",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_BEARER_TOKEN": "entra-token",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_ENDPOINT": "https://my-aoai.openai.azure.com",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_DEPLOYMENT": "gpt-4o-mini",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_API_VERSION": "2024-06-01",
            "AEGIS_LLM_EVALUATOR_REDACT_SENSITIVE": "false",
        },
        clear=False,
    ), patch("app.llm_evaluator.requests.post") as mock_post:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"result":"PASS","reason":"Azure bearer verdict"}'
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        result = evaluate_with_llm("hallucination_comprehensive", "prompt", "response")

    assert result == ("PASS", "Azure bearer verdict")
    called_headers = mock_post.call_args.kwargs.get("headers", {})
    assert called_headers.get("Authorization") == "Bearer entra-token"
    assert "api-key" not in called_headers


def test_llm_evaluator_azure_openai_bearer_requires_token() -> None:
    with patch.dict(
        os.environ,
        {
            "AEGIS_LLM_EVALUATOR_ENABLED": "true",
            "AEGIS_LLM_EVALUATOR_PROVIDER": "azure_openai",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_AUTH_MODE": "bearer_token",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_BEARER_TOKEN": "",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_ENDPOINT": "https://my-aoai.openai.azure.com",
            "AEGIS_LLM_EVALUATOR_AZURE_OPENAI_DEPLOYMENT": "gpt-4o-mini",
        },
        clear=False,
    ):
        result = evaluate_with_llm("pii_regex", "prompt", "response")

    assert result is None
