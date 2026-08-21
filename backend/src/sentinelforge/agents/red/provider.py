"""LLM provider abstraction layer for the Red Agent.

SECURITY ROLE:
The provider is the boundary to Tier 1 (untrusted reasoning). The Red Agent
treats ALL provider output as untrusted data: it is validated against strict
Pydantic schemas and passed through deterministic policy checks before any
execution authority is granted. Providers never receive HMAC keys, database
credentials, or policy configuration.

Provider drivers:
- `OpenAIProvider`, `AnthropicProvider`, `GeminiProvider`: real vendor drivers.
  SDKs are loaded lazily (only when a request is actually made) so constructing
  a driver never requires a paid API or an installed SDK. Requests carry an
  explicit timeout and all SDK errors are mapped to `ProviderAPIError` /
  `ProviderTimeoutError`. A `client_factory` can be injected for deterministic
  tests without network access.
- `OpenAICompatibleProvider`: driver for local/free inference servers that
  expose the OpenAI Chat Completions API (Ollama, LM Studio, vLLM, ...). Uses
  only the standard library so no SDK or API key is required to develop or test
  the architecture.
- `MockProvider`: deterministic provider for unit/integration tests. It runs
  the exact same control-plane code path as production providers.
- `RetryableProvider`: wraps any provider with exponential-backoff retry for
  INFRASTRUCTURE failures only (ProviderAPIError). Malformed-output
  (`SchemaValidationError`) retries remain owned by the agent's schema-retry
  loop and are never retried here.
- `FallbackProvider`: tries a sequence of providers in order, moving to the
  next only on provider API errors.

SECURITY INVARIANT: retries and fallbacks re-run the SAME deterministic
validation chain downstream. They never relax schema, safety, or policy checks.
"""

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence, Type

from pydantic import BaseModel, ValidationError

from sentinelforge.agents.red.exceptions import ProviderAPIError, SchemaValidationError


class ProviderTimeoutError(ProviderAPIError):
    """Raised when an LLM provider request exceeds its configured timeout.

    This is a `ProviderAPIError` subclass so retry/fallback layers treat it as
    an infrastructure failure (retryable) rather than a schema violation.
    """


class LLMProvider(ABC):
    """Abstract interface for any LLM backend consumed by the Red Agent."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        """Generate raw text output for the given prompt.

        Returns:
            Raw text output (NOT yet validated against `response_schema`).

        Raises:
            ProviderAPIError: When the provider fails or is unavailable.
        """
        raise NotImplementedError

    def generate_structured(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Type[BaseModel],
        temperature: float = 0.2,
    ) -> BaseModel:
        """Generate output and validate it against `response_schema`.

        Raises:
            ProviderAPIError: When the provider fails or is unavailable.
            SchemaValidationError: When raw output fails schema validation.
        """
        raw = self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            response_schema=response_schema,
            temperature=temperature,
        )
        try:
            if isinstance(raw, BaseModel):
                return raw
            data = json.loads(raw)
            return response_schema.model_validate(data)
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            raise SchemaValidationError(f"Provider output failed schema validation: {exc}") from exc


class MockProvider(LLMProvider):
    """Deterministic provider for tests.

    Behavior:
    - If `responses` is provided, returns responses in sequence (cycling to
      the last response once exhausted).
    - If `response_schema` is provided during generate() and no explicit
      response is queued, returns a deterministic payload populated from
      `defaults` (or a minimal valid instance).
    - Tracks the number of calls (useful for budget tests).
    - Can be configured to raise ProviderAPIError after `fail_after` calls.
    """

    def __init__(
        self,
        responses: Optional[Sequence[str]] = None,
        fail_after: Optional[int] = None,
    ):
        self._responses = list(responses) if responses else []
        self._fail_after = fail_after
        self.call_count = 0

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        self.call_count += 1
        if self._fail_after is not None and self.call_count > self._fail_after:
            raise ProviderAPIError("mock provider failure injected")

        if self._responses:
            idx = min(self.call_count - 1, len(self._responses) - 1)
            return self._responses[idx]

        if response_schema is not None:
            # Return a deterministic JSON skeleton so schema validation can be
            # exercised without external dependencies.
            sample = self._sample_for_schema(response_schema)
            return json.dumps(sample, default=str)

        return "{}"

    @staticmethod
    def _sample_for_schema(schema: Type[BaseModel]) -> dict:
        """Build a deterministic JSON payload from a Pydantic model schema."""
        try:
            # Try a minimal valid instance via model_fields defaults.
            kwargs = {}
            for name, field in schema.model_fields.items():
                if field.is_required():
                    continue
                if field.default is not None:
                    kwargs[name] = field.default
                elif field.default_factory is not None:
                    kwargs[name] = field.default_factory()
            return schema(**kwargs).model_dump()
        except Exception:
            return {}


class OpenAICompatibleProvider(LLMProvider):
    """Driver for local/free OpenAI Chat Completions-compatible endpoints.

    Targets local inference servers exposing the OpenAI `/chat/completions`
    API (Ollama at `http://localhost:11434/v1`, LM Studio, vLLM, llama.cpp
    server, ...) so the full architecture can be developed and tested WITHOUT
    any paid API access.

    Transport notes:
    - Uses only the Python standard library (no third-party SDK required).
    - `http_post` may be injected for deterministic tests; by default the
      request is sent with an explicit `timeout`.
    - All network failures map to `ProviderAPIError`; timeouts map to
      `ProviderTimeoutError`.
    """

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "ollama",
        timeout: float = 120.0,
        http_post: Optional[Callable[[str, str], str]] = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._http_post = http_post
        self.call_count = 0

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        self.call_count += 1
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "stream": False,
        }
        if response_schema is not None:
            # Ask the server for a JSON object; the schema itself is validated
            # authoritatively by the control plane after this call.
            body["response_format"] = {"type": "json_object"}

        raw = self._post(url, json.dumps(body))
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderAPIError(
                f"Unexpected chat completions response: {exc}"
            ) from exc

        if not content or not isinstance(content, str):
            raise ProviderAPIError("Model returned an empty or non-string completion")
        return content

    def _post(self, url: str, payload: str) -> str:
        """POST `payload` to `url`; returns the raw response body string.

        Timeouts raise `ProviderTimeoutError`; all other transport failures
        raise `ProviderAPIError`. The injected transport is held to the same
        contract as the default urllib transport.
        """
        if self._http_post is not None:
            try:
                return self._http_post(url, payload)
            except TimeoutError as exc:
                raise ProviderTimeoutError(
                    f"OpenAI-compatible endpoint timed out after {self.timeout}s"
                ) from exc
            except ProviderAPIError:
                raise
            except Exception as exc:
                raise ProviderAPIError(
                    f"OpenAI-compatible endpoint error: {exc}"
                ) from exc

        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except TimeoutError as exc:
            raise ProviderTimeoutError(
                f"OpenAI-compatible endpoint timed out after {self.timeout}s"
            ) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise ProviderAPIError(
                f"OpenAI-compatible endpoint unreachable "
                f"({type(reason).__name__}): {reason}"
            ) from exc
        except Exception as exc:
            raise ProviderAPIError(
                f"OpenAI-compatible endpoint error: {exc}"
            ) from exc


class _SdkBackedProvider(LLMProvider):
    """Base helper for vendor SDK-backed providers.

    SDKs are loaded lazily on first request and cached. If the SDK is not
    installed, `generate()` raises `ProviderAPIError` with a clear diagnostic
    instead of failing at construction time. Subclasses declare `_sdk_module`
    and `_build_client`, and may inject a `client_factory` to bypass the SDK
    entirely for deterministic tests.
    """

    _sdk_module: str = ""

    def __init__(self, api_key: str, model: str, temperature: float = 0.2):
        self.api_key = api_key
        self.model = model
        self.default_temperature = temperature
        self._sdk: Any = None

    def _load_sdk(self) -> Any:
        """Import and cache the vendor SDK module (lazy)."""
        if self._sdk is not None:
            return self._sdk
        try:
            import importlib

            self._sdk = importlib.import_module(self._sdk_module)
            return self._sdk
        except ImportError as exc:
            raise ProviderAPIError(
                f"{type(self).__name__} requires SDK '{self._sdk_module}' "
                "which is not installed"
            ) from exc

    def _build_client(self, sdk: Any) -> Any:
        raise NotImplementedError


class OpenAIProvider(_SdkBackedProvider):
    """OpenAI-backed provider driver (gpt-4o, o3-mini, etc.).

    Uses the `openai` SDK. When a `response_schema` is supplied the request
    asks for a JSON object (`response_format={"type": "json_object"}`); the
    schema itself is still validated authoritatively by the control plane.
    """

    _sdk_module = "openai"

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.2,
        timeout: float = 60.0,
        client_factory: Optional[Callable[[], Any]] = None,
    ):
        super().__init__(api_key, model, temperature)
        self.timeout = timeout
        self._client_factory = client_factory
        self._client: Any = None

    @property
    def client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                self._client = self._build_client(self._load_sdk())
        return self._client

    def _build_client(self, sdk: Any) -> Any:
        return sdk.OpenAI(api_key=self.api_key, timeout=self.timeout)

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        client = self.client
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }
        if response_schema is not None:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            completion = client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise _map_openai_error(exc) from exc
        try:
            content = completion.choices[0].message.content
        except (AttributeError, IndexError, KeyError) as exc:
            raise ProviderAPIError(
                f"Unexpected OpenAI completion shape: {exc}"
            ) from exc
        if not content:
            raise ProviderAPIError("OpenAI returned an empty completion")
        return content


class AnthropicProvider(_SdkBackedProvider):
    """Anthropic-backed provider driver (claude-3-5-sonnet, etc.).

    Uses the `anthropic` Messages API.
    """

    _sdk_module = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.2,
        timeout: float = 60.0,
        max_tokens: int = 1024,
        client_factory: Optional[Callable[[], Any]] = None,
    ):
        super().__init__(api_key, model, temperature)
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._client_factory = client_factory
        self._client: Any = None

    @property
    def client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                self._client = self._build_client(self._load_sdk())
        return self._client

    def _build_client(self, sdk: Any) -> Any:
        return sdk.Anthropic(api_key=self.api_key, timeout=self.timeout)

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        client = self.client
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        try:
            message = client.messages.create(**kwargs)
        except Exception as exc:
            raise _map_anthropic_error(exc) from exc

        parts = getattr(message, "content", None) or []
        text = "".join(
            getattr(block, "text", "")
            for block in parts
            if getattr(block, "type", "") == "text"
        )
        if not text:
            raise ProviderAPIError("Anthropic returned an empty completion")
        return text


class GeminiProvider(_SdkBackedProvider):
    """Google Gemini-backed provider driver (gemini-2.0-flash, etc.).

    Uses the `google-genai` SDK's `models.generate_content` API.
    """

    _sdk_module = "google.genai"

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.2,
        timeout: float = 60.0,
        client_factory: Optional[Callable[[], Any]] = None,
    ):
        super().__init__(api_key, model, temperature)
        self.timeout = timeout
        self._client_factory = client_factory
        self._client: Any = None

    @property
    def client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                self._client = self._build_client(self._load_sdk())
        return self._client

    def _build_client(self, sdk: Any) -> Any:
        return sdk.Client(api_key=self.api_key, http_options={"timeout": self.timeout})

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        client = self.client
        config: dict = {
            "system_instruction": system_prompt,
            "temperature": temperature,
        }
        if response_schema is not None:
            config["response_mime_type"] = "application/json"
        try:
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
        except Exception as exc:
            raise _map_gemini_error(exc) from exc

        text = getattr(response, "text", None)
        if not text:
            raise ProviderAPIError("Gemini returned an empty completion")
        return text


@dataclass
class ProviderRetryPolicy:
    """Deterministic retry/backoff policy for provider API failures.

    SECURITY:
    - Retries apply ONLY to infrastructure failures (`ProviderAPIError` and
      subclasses such as `ProviderTimeoutError`). Malformed-output retries
      (`SchemaValidationError`) are owned by the agent's schema-retry loop and
      are NEVER retried here.
    - The policy is Python-owned. The LLM can neither observe nor modify it.
    """

    max_retries: int = 3
    backoff_base_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 8.0

    def delay_for(self, attempt: int) -> float:
        """Return the backoff delay for the given 1-based attempt number."""
        if attempt < 1:
            attempt = 1
        raw = self.backoff_base_seconds * (self.backoff_multiplier ** (attempt - 1))
        return min(raw, self.max_backoff_seconds)


class RetryableProvider(LLMProvider):
    """Wraps an inner provider with exponential-backoff retry on API errors.

    Only `ProviderAPIError` (and subclasses) trigger a retry. Schema failures
    propagate immediately so the agent's schema-retry loop remains the sole
    owner of malformed-output retries.

    NOTE: `generate_structured()` on the wrapper counts as ONE logical LLM call
    for budget purposes even though internal retries may re-request from the
    inner provider.
    """

    def __init__(
        self,
        inner: LLMProvider,
        policy: Optional[ProviderRetryPolicy] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.inner = inner
        self.policy = policy or ProviderRetryPolicy()
        self._sleep = sleep_fn
        self.attempt_count = 0
        self.retry_count = 0

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        attempt = 0
        while True:
            attempt += 1
            self.attempt_count = attempt
            try:
                return self.inner.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_schema=response_schema,
                    temperature=temperature,
                )
            except ProviderAPIError as exc:
                if attempt > self.policy.max_retries:
                    raise
                self.retry_count += 1
                self._sleep(self.policy.delay_for(attempt))


class FallbackProvider(LLMProvider):
    """Tries a sequence of providers in order, moving on API errors.

    Providers are tried left-to-right. A provider that raises
    `ProviderAPIError` (including timeouts) is skipped; `SchemaValidationError`
    is NOT an API failure and propagates immediately so malformed output never
    silently switches providers.
    """

    def __init__(self, providers: Sequence[LLMProvider]):
        if not providers:
            raise ValueError("FallbackProvider requires at least one provider")
        self.providers = list(providers)

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.2,
    ) -> str:
        errors: list[ProviderAPIError] = []
        for provider in self.providers:
            try:
                return provider.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_schema=response_schema,
                    temperature=temperature,
                )
            except ProviderAPIError as exc:
                errors.append(exc)
                continue
        last = errors[-1] if errors else ProviderAPIError("no providers configured")
        raise ProviderAPIError(
            f"all {len(self.providers)} provider(s) failed; last error: {last}"
        ) from last


def _map_openai_error(exc: Exception) -> ProviderAPIError:
    """Map OpenAI SDK exceptions to the provider error hierarchy."""
    name = type(exc).__name__
    if name in ("APITimeoutError", "APIConnectionError") or isinstance(exc, TimeoutError):
        return ProviderTimeoutError(f"OpenAI provider timed out: {exc}")
    return ProviderAPIError(f"OpenAI provider error ({name}): {exc}")


def _map_anthropic_error(exc: Exception) -> ProviderAPIError:
    """Map Anthropic SDK exceptions to the provider error hierarchy."""
    name = type(exc).__name__
    if name in ("APITimeoutError", "APIConnectionError") or isinstance(exc, TimeoutError):
        return ProviderTimeoutError(f"Anthropic provider timed out: {exc}")
    return ProviderAPIError(f"Anthropic provider error ({name}): {exc}")


def _map_gemini_error(exc: Exception) -> ProviderAPIError:
    """Map Google-genai SDK exceptions to the provider error hierarchy."""
    name = type(exc).__name__
    if name in ("APITimeoutError", "ClientError") or isinstance(exc, TimeoutError):
        return ProviderTimeoutError(f"Gemini provider timed out: {exc}")
    return ProviderAPIError(f"Gemini provider error ({name}): {exc}")
