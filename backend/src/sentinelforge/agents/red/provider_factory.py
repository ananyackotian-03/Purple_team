"""LLM Provider Factory — creates providers from environment configuration.

SECURITY:
- API keys are NEVER logged, printed, stored in DB, or passed to targets.
- Configuration is read from environment variables only.
- If SDK is missing, a clear error is raised (never silently degraded).
- MockProvider works without any credentials.
"""

import os
from typing import Optional

from sentinelforge.agents.red.provider import (
    AnthropicProvider,
    FallbackProvider,
    GeminiProvider,
    LLMProvider,
    MockProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    RetryableProvider,
)


class ProviderConfigurationError(Exception):
    """Raised when provider configuration is invalid or incomplete."""


def create_provider_from_env(
    provider_name: Optional[str] = None,
    retry: bool = True,
) -> LLMProvider:
    """Create an LLMProvider from environment variables.

    Environment variables:
        SENTINELFORGE_LLM_PROVIDER: mock | openai | anthropic | gemini | openai-compatible
        OPENAI_API_KEY: OpenAI API key (required for openai)
        OPENAI_MODEL: Model name (default: gpt-4o)
        OPENAI_BASE_URL: Custom base URL (optional)
        ANTHROPIC_API_KEY: Anthropic API key (required for anthropic)
        ANTHROPIC_MODEL: Model name (default: claude-sonnet-4-20250514)
        GEMINI_API_KEY: Google Gemini API key (required for gemini)
        GEMINI_MODEL: Model name (default: gemini-2.0-flash)
        OLLAMA_MODEL: Model name for OpenAI-compatible (default: llama3.2)
        OLLAMA_BASE_URL: Base URL (default: http://localhost:11434/v1)

    Args:
        provider_name: Override for SENTINELFORGE_LLM_PROVIDER env var.
        retry: Wrap with RetryableProvider for infrastructure failures.

    Returns:
        Configured LLMProvider instance.

    Raises:
        ProviderConfigurationError: If configuration is invalid.
    """
    name = (provider_name or os.environ.get("SENTINELFORGE_LLM_PROVIDER", "mock")).lower()

    provider: LLMProvider

    if name == "mock":
        provider = MockProvider()

    elif name == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ProviderConfigurationError(
                "OPENAI_API_KEY environment variable is required for openai provider"
            )
        model = os.environ.get("OPENAI_MODEL", "gpt-4o")
        base_url = os.environ.get("OPENAI_BASE_URL")
        try:
            if base_url:
                provider = OpenAIProvider(api_key=api_key, model=model)
                # OpenAIProvider doesn't accept base_url directly; use
                # OpenAICompatibleProvider for custom base URLs instead.
                provider = OpenAICompatibleProvider(
                    model=model, base_url=base_url, api_key=api_key
                )
            else:
                provider = OpenAIProvider(api_key=api_key, model=model)
        except Exception as exc:
            raise ProviderConfigurationError(
                f"Failed to create OpenAI provider: {exc}"
            ) from exc

    elif name == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ProviderConfigurationError(
                "ANTHROPIC_API_KEY environment variable is required for anthropic provider"
            )
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        try:
            provider = AnthropicProvider(api_key=api_key, model=model)
        except Exception as exc:
            raise ProviderConfigurationError(
                f"Failed to create Anthropic provider: {exc}"
            ) from exc

    elif name == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ProviderConfigurationError(
                "GEMINI_API_KEY or GOOGLE_API_KEY environment variable is required for gemini provider"
            )
        model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        try:
            provider = GeminiProvider(api_key=api_key, model=model)
        except Exception as exc:
            raise ProviderConfigurationError(
                f"Failed to create Gemini provider: {exc}"
            ) from exc

    elif name == "openai-compatible":
        model = os.environ.get("OLLAMA_MODEL", "llama3.2")
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        api_key = os.environ.get("OPENAI_API_KEY", "ollama")
        provider = OpenAICompatibleProvider(
            model=model, base_url=base_url, api_key=api_key
        )

    else:
        raise ProviderConfigurationError(
            f"Unknown provider: {name!r}. "
            f"Supported: mock, openai, anthropic, gemini, openai-compatible"
        )

    if retry:
        provider = RetryableProvider(inner=provider)

    return provider


def is_live_provider_available(provider_name: Optional[str] = None) -> bool:
    """Check if a real (non-mock) provider can be instantiated.

    Returns True only if the provider is configured AND the SDK is installed.
    Never raises.
    """
    name = (provider_name or os.environ.get("SENTINELFORGE_LLM_PROVIDER", "mock")).lower()
    if name == "mock":
        return True
    try:
        create_provider_from_env(provider_name=name, retry=False)
        return True
    except (ProviderConfigurationError, Exception):
        return False
