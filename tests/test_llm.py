"""The API call is exercised against a local stub, never the real thing."""

from __future__ import annotations

import pytest

from re_ai.analysis import analyze_bytes
from re_ai.llm import (
    DEFAULT_BASE_URL,
    LLMConfig,
    LLMError,
    build_prompt,
    draft_analysis,
    resolve_config,
)


def env(**overrides):
    base = {
        "RE_AI_BASE_URL": "http://127.0.0.1:9/v1",
        "RE_AI_API_KEY": "re-ai-key",
        "RE_AI_MODEL": "re-ai-model",
        "OPENAI_BASE_URL": "http://openai.test/v1",
        "OPENAI_API_KEY": "openai-key",
        "OPENAI_MODEL": "openai-model",
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


def test_re_ai_variables_win():
    config = resolve_config(env())
    assert config.base_url == "http://127.0.0.1:9/v1"
    assert config.api_key == "re-ai-key"
    assert config.model == "re-ai-model"


def test_openai_variables_are_the_fallback():
    config = resolve_config(env(RE_AI_BASE_URL=None, RE_AI_API_KEY=None, RE_AI_MODEL=None))
    assert config.base_url == "http://openai.test/v1"
    assert config.api_key == "openai-key"
    assert config.model == "openai-model"


def test_default_base_url_when_only_a_key_is_set():
    config = resolve_config(env(RE_AI_BASE_URL=None, OPENAI_BASE_URL=None))
    assert config.base_url == DEFAULT_BASE_URL


def test_explicit_model_wins():
    assert resolve_config(env(), model="override").model == "override"


def test_missing_key_raises():
    with pytest.raises(LLMError, match="API key"):
        resolve_config(env(RE_AI_API_KEY=None, OPENAI_API_KEY=None))


def test_endpoint_is_normalised():
    assert LLMConfig("http://x/v1", "k", "m").endpoint == "http://x/v1/chat/completions"
    assert LLMConfig("http://x/v1/", "k", "m").endpoint == "http://x/v1/chat/completions"
    assert (
        LLMConfig("http://x/v1/chat/completions", "k", "m").endpoint
        == "http://x/v1/chat/completions"
    )


def test_prompt_contains_the_facts(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes, name="fixture.exe")
    prompt = build_prompt(analysis)
    assert analysis.sha256 in prompt
    assert "KERNEL32.dll" in prompt
    assert "What it appears to do" in prompt
    assert len(prompt) < 8000


def test_draft_analysis_sends_a_chat_request(fake_llm_server, synthetic_pe_bytes):
    config = LLMConfig(fake_llm_server.base_url, "test-key", "fake-model")
    analysis = analyze_bytes(synthetic_pe_bytes, name="fixture.exe")
    text, model = draft_analysis(analysis, config=config)

    assert "console program" in text
    assert model == "fake-model"
    assert len(fake_llm_server.requests) == 1
    request = fake_llm_server.requests[0]
    assert request["path"] == "/v1/chat/completions"
    assert request["authorization"] == "Bearer test-key"
    assert request["body"]["model"] == "fake-model"
    roles = [message["role"] for message in request["body"]["messages"]]
    assert roles == ["system", "user"]
    assert analysis.sha256 in request["body"]["messages"][1]["content"]


def test_draft_analysis_reads_the_environment(fake_llm_server, synthetic_pe_bytes, monkeypatch):
    monkeypatch.setenv("RE_AI_BASE_URL", fake_llm_server.base_url)
    monkeypatch.setenv("RE_AI_API_KEY", "env-key")
    monkeypatch.setenv("RE_AI_MODEL", "env-model")
    text, model = draft_analysis(analyze_bytes(synthetic_pe_bytes))
    assert "console program" in text
    assert model == "fake-model"
    assert fake_llm_server.requests[0]["body"]["model"] == "env-model"


def test_http_error_is_wrapped(fake_llm_server, synthetic_pe_bytes):
    fake_llm_server.status = 401
    fake_llm_server.raw_body = '{"error": "bad key"}'
    config = LLMConfig(fake_llm_server.base_url, "k", "m")
    with pytest.raises(LLMError, match="HTTP 401"):
        draft_analysis(analyze_bytes(synthetic_pe_bytes), config=config)


def test_invalid_json_is_wrapped(fake_llm_server, synthetic_pe_bytes):
    fake_llm_server.raw_body = "<html>not json</html>"
    config = LLMConfig(fake_llm_server.base_url, "k", "m")
    with pytest.raises(LLMError, match="invalid JSON"):
        draft_analysis(analyze_bytes(synthetic_pe_bytes), config=config)


def test_empty_choices_is_wrapped(fake_llm_server, synthetic_pe_bytes):
    fake_llm_server.raw_body = '{"choices": []}'
    config = LLMConfig(fake_llm_server.base_url, "k", "m")
    with pytest.raises(LLMError, match="no choices"):
        draft_analysis(analyze_bytes(synthetic_pe_bytes), config=config)


def test_dashes_are_removed_from_model_output(fake_llm_server, synthetic_pe_bytes):
    fake_llm_server.content = "It opens a socket \u2014 then waits."
    config = LLMConfig(fake_llm_server.base_url, "k", "m")
    text, _ = draft_analysis(analyze_bytes(synthetic_pe_bytes), config=config)
    assert "\u2014" not in text
    assert text == "It opens a socket, then waits."
