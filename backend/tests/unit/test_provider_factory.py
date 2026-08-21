"""SentinelForge — Unit Tests for Provider Factory."""

import os
import pytest
from unittest.mock import patch

from sentinelforge.agents.red.provider import MockProvider, RetryableProvider
from sentinelforge.agents.red.provider_factory import (
    ProviderConfigurationError,
    create_provider_from_env,
    is_live_provider_available,
)


class TestCreateProviderFromEnv:
    def test_mock_provider_default(self):
        provider = create_provider_from_env(provider_name="mock", retry=False)
        assert isinstance(provider, MockProvider)

    def test_mock_provider_explicit(self):
        provider = create_provider_from_env(provider_name="mock", retry=False)
        assert isinstance(provider, MockProvider)

    def test_retry_wrapper(self):
        provider = create_provider_from_env(provider_name="mock", retry=True)
        assert isinstance(provider, RetryableProvider)

    def test_unknown_provider_raises(self):
        with pytest.raises(ProviderConfigurationError, match="Unknown provider"):
            create_provider_from_env(provider_name="nonexistent", retry=False)

    def test_openai_missing_key_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ProviderConfigurationError, match="OPENAI_API_KEY"):
                create_provider_from_env(provider_name="openai", retry=False)

    def test_anthropic_missing_key_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ProviderConfigurationError, match="ANTHROPIC_API_KEY"):
                create_provider_from_env(provider_name="anthropic", retry=False)

    def test_gemini_missing_key_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ProviderConfigurationError, match="GEMINI_API_KEY"):
                create_provider_from_env(provider_name="gemini", retry=False)

    def test_env_var_override(self):
        with patch.dict(os.environ, {"SENTINELFORGE_LLM_PROVIDER": "mock"}):
            provider = create_provider_from_env(retry=False)
            assert isinstance(provider, MockProvider)

    def test_openai_compatible_provider(self):
        provider = create_provider_from_env(
            provider_name="openai-compatible", retry=False
        )
        from sentinelforge.agents.red.provider import OpenAICompatibleProvider
        assert isinstance(provider, OpenAICompatibleProvider)


class TestIsLiveProviderAvailable:
    def test_mock_always_available(self):
        assert is_live_provider_available("mock") is True

    def test_unknown_provider_not_available(self):
        assert is_live_provider_available("nonexistent") is False

    def test_default_is_mock(self):
        assert is_live_provider_available() is True
