"""Test suite for the SentinelForge Red Agent LLM provider layer.

Covers the Step-1 provider milestone:
- Local/free OpenAI-compatible driver (`OpenAICompatibleProvider`).
- Real vendor drivers (`OpenAIProvider`, `AnthropicProvider`, `GeminiProvider`)
  via injected fake clients (no network, no SDK, no API key required).
- Lazy SDK loading: constructing a vendor driver never requires the SDK.
- `ProviderRetryPolicy` exponential backoff + `RetryableProvider`.
- `FallbackProvider` fallback chain semantics.
- Timeout and provider-failure mapping.

SECURITY:
Retries/fallbacks never relax schema or safety checks: `SchemaValidationError`
is never retried by `RetryableProvider` and never swallowed by
`FallbackProvider`. Provider output is raw text until the control plane
validates it.

Every test here actually runs in this environment (PASS). Live-vendor and
local-endpoint network tests are intentionally NOT included so the suite has no
network or paid-API dependency.
"""

import importlib
import json

import pytest

from sentinelforge.agents.red.exceptions import ProviderAPIError, SchemaValidationError
from sentinelforge.agents.red.provider import (
    AnthropicProvider,
    FallbackProvider,
    GeminiProvider,
    LLMProvider,
    MockProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    ProviderRetryPolicy,
    ProviderTimeoutError,
    RetryableProvider,
)
from sentinelforge.agents.red.schemas import RedAgentDecision


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _valid_decision_json() -> str:
    return json.dumps(
        {
            "decision": "TERMINATE_OBJECTIVE",
            "hypothesis": "Objective fully explored.",
            "reasoning_summary": "No new experiments remain.",
        }
    )


def _ok_payload(content=None) -> str:
    """OpenAI chat-completions-style response with `content` (default valid)."""
    return json.dumps(
        {
            "choices": [
                {"message": {"content": content if content is not None else _valid_decision_json()}}
            ]
        }
    )


# ---------------------------------------------------------------------------
# OpenAICompatibleProvider (local/free endpoint, stdlib transport)
# ---------------------------------------------------------------------------
class TestOpenAICompatibleProvider:
    def test_valid_response_parsed(self):
        provider = OpenAICompatibleProvider(
            model="local-model", http_post=lambda url, body: _ok_payload()
        )
        out = provider.generate("prompt", "sys")
        assert json.loads(out)["decision"] == "TERMINATE_OBJECTIVE"

    def test_schema_request_asks_for_json_object(self):
        seen = {}

        def fake_post(url, body):
            seen["body"] = json.loads(body)
            return _ok_payload()

        provider = OpenAICompatibleProvider(model="m", http_post=fake_post)
        provider.generate("p", "sys", response_schema=RedAgentDecision)
        assert seen["body"]["response_format"] == {"type": "json_object"}
        assert seen["body"]["stream"] is False
        assert seen["body"]["messages"][0]["role"] == "system"
        assert seen["body"]["messages"][1]["role"] == "user"

    def test_generate_structured_returns_validated_model(self):
        provider = OpenAICompatibleProvider(
            model="m", http_post=lambda url, body: _ok_payload()
        )
        decision = provider.generate_structured("p", "sys", response_schema=RedAgentDecision)
        assert isinstance(decision, RedAgentDecision)

    def test_malformed_response_raises_api_error(self):
        provider = OpenAICompatibleProvider(
            model="m", http_post=lambda url, body: '{"choices": []}'
        )
        with pytest.raises(ProviderAPIError):
            provider.generate("p", "sys")

    def test_empty_content_raises(self):
        provider = OpenAICompatibleProvider(
            model="m", http_post=lambda url, body: _ok_payload(content="")
        )
        with pytest.raises(ProviderAPIError):
            provider.generate("p", "sys")

    def test_timeout_maps_to_provider_timeout(self):
        def timeout_post(url, body):
            raise TimeoutError("socket timed out")

        provider = OpenAICompatibleProvider(model="m", http_post=timeout_post)
        with pytest.raises(ProviderTimeoutError):
            provider.generate("p", "sys")

    def test_connection_failure_maps_to_api_error(self):
        def refused_post(url, body):
            raise ConnectionError("connection refused")

        provider = OpenAICompatibleProvider(model="m", http_post=refused_post)
        with pytest.raises(ProviderAPIError) as exc_info:
            provider.generate("p", "sys")
        assert not isinstance(exc_info.value, ProviderTimeoutError)

    def test_call_count_tracks(self):
        provider = OpenAICompatibleProvider(
            model="m", http_post=lambda url, body: _ok_payload()
        )
        provider.generate("p", "sys")
        provider.generate("p", "sys")
        assert provider.call_count == 2


# ---------------------------------------------------------------------------
# ProviderRetryPolicy + RetryableProvider
# ---------------------------------------------------------------------------
class _FlakyProvider(LLMProvider):
    """Inner provider that raises ProviderAPIError for the first N calls."""

    def __init__(self, fail_times: int, response: str = "ok", fail_with=None):
        self.fail_times = fail_times
        self.response = response
        self.fail_with = fail_with or ProviderAPIError
        self.calls = 0

    def generate(self, prompt, system_prompt, response_schema=None, temperature=0.2):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.fail_with("injected failure")
        return self.response


class TestProviderRetryPolicy:
    def test_default_delay_sequence(self):
        policy = ProviderRetryPolicy()
        assert [policy.delay_for(i) for i in (1, 2, 3, 4)] == [1.0, 2.0, 4.0, 8.0]

    def test_backoff_capped(self):
        policy = ProviderRetryPolicy(max_backoff_seconds=2.0)
        assert [policy.delay_for(i) for i in (1, 2, 3, 4)] == [1.0, 2.0, 2.0, 2.0]

    def test_delay_for_clamps_to_one(self):
        assert ProviderRetryPolicy().delay_for(0) == 1.0


class TestRetryableProvider:
    def test_retries_then_succeeds(self):
        sleeps = []
        inner = _FlakyProvider(fail_times=1)
        provider = RetryableProvider(inner, sleep_fn=sleeps.append)
        assert provider.generate("p", "sys") == "ok"
        assert inner.calls == 2
        assert provider.retry_count == 1
        assert sleeps == [1.0]

    def test_exhausts_retries_raises(self):
        sleeps = []
        inner = _FlakyProvider(fail_times=999)
        provider = RetryableProvider(inner, sleep_fn=sleeps.append)
        with pytest.raises(ProviderAPIError):
            provider.generate("p", "sys")
        # initial attempt + 3 backoff retries (1s, 2s, 4s)
        assert inner.calls == 4
        assert provider.retry_count == 3
        assert sleeps == [1.0, 2.0, 4.0]

    def test_success_on_first_attempt_no_sleep(self):
        sleeps = []
        inner = _FlakyProvider(fail_times=0)
        provider = RetryableProvider(inner, sleep_fn=sleeps.append)
        assert provider.generate("p", "sys") == "ok"
        assert provider.retry_count == 0
        assert sleeps == []

    def test_does_not_retry_schema_errors(self):
        """SchemaValidationError is NOT an infrastructure failure."""
        sleeps = []
        inner = _FlakyProvider(fail_times=999, fail_with=SchemaValidationError)
        provider = RetryableProvider(inner, sleep_fn=sleeps.append)
        with pytest.raises(SchemaValidationError):
            provider.generate("p", "sys")
        assert inner.calls == 1
        assert provider.retry_count == 0
        assert sleeps == []

    def test_timeout_errors_are_retried(self):
        """ProviderTimeoutError is a ProviderAPIError subclass -> retried."""
        sleeps = []
        inner = _FlakyProvider(fail_times=2, fail_with=ProviderTimeoutError)
        provider = RetryableProvider(inner, sleep_fn=sleeps.append)
        assert provider.generate("p", "sys") == "ok"
        assert provider.retry_count == 2
        assert sleeps == [1.0, 2.0]


# ---------------------------------------------------------------------------
# FallbackProvider
# ---------------------------------------------------------------------------
class TestFallbackProvider:
    def test_primary_success_no_fallback(self):
        primary = MockProvider(responses=["A"])
        secondary = MockProvider(responses=["B"])
        provider = FallbackProvider([primary, secondary])
        assert provider.generate("p", "sys") == "A"
        assert primary.call_count == 1
        assert secondary.call_count == 0

    def test_fallback_on_api_error(self):
        primary = MockProvider(responses=["A"], fail_after=0)
        secondary = MockProvider(responses=["B"])
        provider = FallbackProvider([primary, secondary])
        assert provider.generate("p", "sys") == "B"
        assert secondary.call_count == 1

    def test_all_fail_raises(self):
        primary = MockProvider(responses=["A"], fail_after=0)
        secondary = MockProvider(responses=["B"], fail_after=0)
        provider = FallbackProvider([primary, secondary])
        with pytest.raises(ProviderAPIError) as exc_info:
            provider.generate("p", "sys")
        assert "all 2 provider(s) failed" in str(exc_info.value)

    def test_schema_error_not_swallowed_by_fallback(self):
        """A malformed-output schema error must NOT silently switch providers."""
        primary = MockProvider(responses=["not valid json"])
        secondary = MockProvider(responses=[_valid_decision_json()])
        provider = FallbackProvider([primary, secondary])
        with pytest.raises(SchemaValidationError):
            provider.generate_structured("p", "sys", response_schema=RedAgentDecision)
        assert secondary.call_count == 0

    def test_requires_at_least_one_provider(self):
        with pytest.raises(ValueError):
            FallbackProvider([])


# ---------------------------------------------------------------------------
# Vendor drivers (injected fake clients; no SDK, no network, no API key)
# ---------------------------------------------------------------------------
# Fake OpenAI-compatible client shape
class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _FakeChoice:
    def __init__(self, content):
        self.message = _FakeMsg(content)


class _FakeCompletions:
    def __init__(self, result):
        self.result = result
        self.choices = [result] if isinstance(result, _FakeChoice) else None
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return _FakeCompletions(self.result)


class _FakeOpenAIChat:
    def __init__(self, result):
        self.completions = _FakeCompletions(result)


class _FakeOpenAIClient:
    def __init__(self, result):
        self.chat = _FakeOpenAIChat(result)


# Fake error classes whose NAME matches vendor SDK error names.
class APITimeoutError(Exception):
    pass


class RateLimitError(Exception):
    pass


# Fake Anthropic client shape
class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeAnthropicMessage:
    def __init__(self, content):
        self.content = content


class _FakeAnthropicMessages:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _FakeAnthropicClient:
    def __init__(self, result):
        self.messages = _FakeAnthropicMessages(result)


# Fake Google-genai client shape
class _FakeGeminiResponse:
    def __init__(self, text):
        self.text = text


class _FakeGeminiModels:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _FakeGeminiClient:
    def __init__(self, result):
        self.models = _FakeGeminiModels(result)


class TestVendorDriverConstruction:
    def test_constructible_without_sdk(self):
        """Lazy SDK loading: construction never requires the vendor SDK."""
        OpenAIProvider(api_key="k", model="gpt-4o")
        AnthropicProvider(api_key="k", model="claude-3-5-sonnet")
        GeminiProvider(api_key="k", model="gemini-2.0-flash")

    def test_missing_sdk_raises_on_generate(self, monkeypatch):
        """Simulate SDK absent -> ProviderAPIError with SDK message."""
        def _fail_import(name, *args, **kwargs):
            if name == "openai":
                raise ImportError("No module named 'openai'")
            return _orig_import(name, *args, **kwargs)

        _orig_import = importlib.import_module
        monkeypatch.setattr(importlib, "import_module", _fail_import)
        provider = OpenAIProvider(api_key="k", model="gpt-4o")
        provider._sdk = None  # reset cached SDK
        with pytest.raises(ProviderAPIError) as exc_info:
            provider.generate("p", "sys")
        assert "SDK" in str(exc_info.value)

    def test_anthropic_missing_sdk_raises(self):
        with pytest.raises(ProviderAPIError):
            AnthropicProvider(api_key="k", model="claude").generate("p", "sys")

    def test_gemini_missing_sdk_raises(self):
        with pytest.raises(ProviderAPIError):
            GeminiProvider(api_key="k", model="gemini").generate("p", "sys")


class TestOpenAIProviderDriver:
    def test_generate_with_fake_client(self):
        client = _FakeOpenAIClient(_FakeChoice("hello"))
        provider = OpenAIProvider(api_key="k", model="gpt-4o", client_factory=lambda: client)
        assert provider.generate("p", "sys") == "hello"
        assert client.chat.completions.calls[0]["model"] == "gpt-4o"

    def test_schema_request_uses_json_object_format(self):
        client = _FakeOpenAIClient(_FakeChoice(_valid_decision_json()))
        provider = OpenAIProvider(api_key="k", model="m", client_factory=lambda: client)
        provider.generate("p", "sys", response_schema=RedAgentDecision)
        assert client.chat.completions.calls[0]["response_format"] == {"type": "json_object"}

    def test_empty_content_raises(self):
        client = _FakeOpenAIClient(_FakeChoice(""))
        provider = OpenAIProvider(api_key="k", model="m", client_factory=lambda: client)
        with pytest.raises(ProviderAPIError):
            provider.generate("p", "sys")

    def test_sdk_timeout_mapped_to_provider_timeout(self):
        client = _FakeOpenAIClient(APITimeoutError("gateway timeout"))
        provider = OpenAIProvider(api_key="k", model="m", client_factory=lambda: client)
        with pytest.raises(ProviderTimeoutError):
            provider.generate("p", "sys")

    def test_sdk_rate_limit_mapped_to_api_error(self):
        client = _FakeOpenAIClient(RateLimitError("429"))
        provider = OpenAIProvider(api_key="k", model="m", client_factory=lambda: client)
        with pytest.raises(ProviderAPIError) as exc_info:
            provider.generate("p", "sys")
        assert not isinstance(exc_info.value, ProviderTimeoutError)


class TestAnthropicProviderDriver:
    def test_generate_with_fake_client(self):
        msg = _FakeAnthropicMessage([_FakeTextBlock("hello")])
        client = _FakeAnthropicClient(msg)
        provider = AnthropicProvider(api_key="k", model="claude", client_factory=lambda: client)
        assert provider.generate("p", "sys") == "hello"
        call = client.messages.calls[0]
        assert call["model"] == "claude"
        assert call["system"] == "sys"
        assert call["messages"] == [{"role": "user", "content": "p"}]

    def test_empty_content_raises(self):
        client = _FakeAnthropicClient(_FakeAnthropicMessage([]))
        provider = AnthropicProvider(api_key="k", model="claude", client_factory=lambda: client)
        with pytest.raises(ProviderAPIError):
            provider.generate("p", "sys")


class TestGeminiProviderDriver:
    def test_generate_with_fake_client(self):
        client = _FakeGeminiClient(_FakeGeminiResponse("hello"))
        provider = GeminiProvider(api_key="k", model="gemini", client_factory=lambda: client)
        assert provider.generate("p", "sys") == "hello"
        call = client.models.calls[0]
        assert call["model"] == "gemini"
        assert call["config"]["system_instruction"] == "sys"

    def test_schema_request_requests_json_mime(self):
        client = _FakeGeminiClient(_FakeGeminiResponse(_valid_decision_json()))
        provider = GeminiProvider(api_key="k", model="gemini", client_factory=lambda: client)
        provider.generate("p", "sys", response_schema=RedAgentDecision)
        assert client.models.calls[0]["config"]["response_mime_type"] == "application/json"


# ---------------------------------------------------------------------------
# Composition: retry + fallback + structured calls
# ---------------------------------------------------------------------------
class TestProviderComposition:
    def test_retryable_wrapping_fallback(self):
        primary = MockProvider(responses=["A"], fail_after=0)  # always fails
        secondary = _FlakyProvider(fail_times=1, response="B")  # fails once, then succeeds
        fallback = FallbackProvider([primary, secondary])
        sleeps = []
        provider = RetryableProvider(fallback, sleep_fn=sleeps.append)
        assert provider.generate("p", "sys") == "B"
        assert provider.retry_count == 1
        assert sleeps == [1.0]

    def test_generate_structured_through_retryable(self):
        inner = MockProvider(responses=[_valid_decision_json()])
        provider = RetryableProvider(inner)
        decision = provider.generate_structured("p", "sys", response_schema=RedAgentDecision)
        assert isinstance(decision, RedAgentDecision)

    def test_generate_structured_through_fallback(self):
        primary = MockProvider(responses=[_valid_decision_json()])
        provider = FallbackProvider([primary, MockProvider(responses=["fallback"])])
        decision = provider.generate_structured("p", "sys", response_schema=RedAgentDecision)
        assert isinstance(decision, RedAgentDecision)

    def test_wrappers_are_llm_providers(self):
        assert isinstance(RetryableProvider(MockProvider()), LLMProvider)
        assert isinstance(FallbackProvider([MockProvider()]), LLMProvider)
