"""SentinelForge — Real LLM E2E Test.

This test exercises the complete E2E workflow with a real LLM provider.
It is BLOCKED when credentials/SDKs are unavailable.

Classification: LIVE-LLM-VERIFIED (or BLOCKED)
"""

import os
import pytest
from pydantic import BaseModel

from sentinelforge.agents.red.provider_factory import (
    create_provider_from_env,
    is_live_provider_available,
)


def _has_real_provider():
    """Check if a non-mock real provider is configured and available."""
    name = os.environ.get("SENTINELFORGE_LLM_PROVIDER", "mock").lower()
    if name == "mock":
        return False
    return is_live_provider_available(name)


pytestmark = pytest.mark.skipif(
    not _has_real_provider(),
    reason="LIVE LLM TEST: BLOCKED -- configure SENTINELFORGE_LLM_PROVIDER + API key",
)


class TestRealLLME2E:
    def test_provider_factory_creates_live_provider(self):
        provider = create_provider_from_env(retry=False)
        assert provider is not None

    def test_live_provider_generate(self):
        provider = create_provider_from_env(retry=False)
        response = provider.generate(
            prompt="Return ONLY the word hello in lowercase. Nothing else.",
            system_prompt="You are a helpful assistant. Respond only with the requested word.",
            temperature=0.0,
        )
        assert "hello" in response.lower()

    def test_live_provider_structured_output(self):
        class TestSchema(BaseModel):
            answer: str
            confidence: float

        provider = create_provider_from_env(retry=False)
        result = provider.generate_structured(
            prompt='Return exactly this JSON: {"answer": "yes", "confidence": 0.95}',
            system_prompt="Respond with a JSON object matching the schema: {answer: string, confidence: float}",
            response_schema=TestSchema,
            temperature=0.0,
        )
        assert isinstance(result, TestSchema)


if not _has_real_provider():
    @pytest.fixture(autouse=True)
    def _block_live_tests():
        pytest.skip("LIVE LLM: BLOCKED -- configure SENTINELFORGE_LLM_PROVIDER + API key")
