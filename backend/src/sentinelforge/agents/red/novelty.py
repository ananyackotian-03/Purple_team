"""Deterministic strategy fingerprinting and novelty evaluation.

SECURITY ROLE:
Novelty evaluation is fully deterministic and lives in the control plane.
The LLM may CLAIM a novelty category, but only this evaluator decides. This
prevents cosmetic re-submissions (e.g. "whoami " vs "whoami") from causing
wasteful or repetitive executions (T-10).
"""

import hashlib
import re
from enum import Enum
from typing import Iterable, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from sentinelforge.agents.red.schemas import ActionProposalSpec

# Below this command-structure similarity a candidate is treated as NOVEL even
# if technique + executable match a previous strategy.
SIMILARITY_THRESHOLD = 0.85

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


class NoveltyStatus(str, Enum):
    NOVEL = "NOVEL"
    SIMILAR = "SIMILAR"
    DUPLICATE = "DUPLICATE"


class StrategyFingerprint(BaseModel):
    """Deterministic characterization of a proposed strategy."""

    objective_id: UUID
    primary_technique: str
    normalized_executable: str
    normalized_command_pattern: str
    action_types: List[str]
    target_resource: str
    observable_classes: List[str]
    composite_hash: str

    @classmethod
    def create(
        cls,
        objective_id: UUID,
        actions: List[ActionProposalSpec],
    ) -> "StrategyFingerprint":
        """Build a canonical fingerprint from proposed actions.

        Normalization sorts actions so equivalent strategies in different
        orders produce the same fingerprint.
        """
        if not actions:
            raise ValueError("cannot fingerprint a strategy with no actions")

        norm_actions = []
        for action in actions:
            norm_cmd = _normalize_command(action.executable, action.arguments)
            norm_actions.append(norm_cmd)
        norm_actions.sort()

        raw_repr = f"{objective_id}|{'|'.join(norm_actions)}"
        composite_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

        return cls(
            objective_id=objective_id,
            primary_technique=actions[0].technique_id,
            normalized_executable=actions[0].executable,
            normalized_command_pattern=";".join(norm_actions),
            action_types=["process_exec"] * len(actions),
            target_resource=actions[0].target,
            observable_classes=["process_creation"] * len(actions),
            composite_hash=composite_hash,
        )

    def command_tokens(self) -> List[str]:
        """Lowercased, whitespace-stable token list from the command pattern."""
        return _TOKEN_SPLIT_RE.split(self.normalized_command_pattern.lower())


class NoveltyEvaluation(BaseModel):
    """Result of comparing a candidate fingerprint against prior strategies."""

    status: NoveltyStatus
    similarity_score: float = Field(ge=0.0, le=1.0)
    reason: str
    fingerprint: StrategyFingerprint


class NoveltyEvaluator:
    """Compares a candidate StrategyFingerprint against prior strategies."""

    def __init__(
        self,
        previous_fingerprints: Optional[Iterable[StrategyFingerprint]] = None,
    ):
        self._previous = list(previous_fingerprints or [])

    def register(self, fingerprint: StrategyFingerprint) -> None:
        """Add a fingerprint to the prior-history set (e.g. after execution)."""
        self._previous.append(fingerprint)

    @property
    def history_count(self) -> int:
        return len(self._previous)

    def evaluate(self, candidate: StrategyFingerprint) -> NoveltyEvaluation:
        """Classify a candidate as DUPLICATE, SIMILAR, or NOVEL."""
        if not self._previous:
            return NoveltyEvaluation(
                status=NoveltyStatus.NOVEL,
                similarity_score=0.0,
                reason="No prior strategy history; candidate is NOVEL.",
                fingerprint=candidate,
            )

        for prior in self._previous:
            if prior.composite_hash == candidate.composite_hash:
                return NoveltyEvaluation(
                    status=NoveltyStatus.DUPLICATE,
                    similarity_score=1.0,
                    reason="Composite fingerprint exactly matches a prior strategy.",
                    fingerprint=candidate,
                )

        best_similarity = 0.0
        for prior in self._previous:
            if (
                prior.primary_technique == candidate.primary_technique
                and prior.normalized_executable == candidate.normalized_executable
            ):
                best_similarity = max(
                    best_similarity,
                    _token_jaccard(prior.command_tokens(), candidate.command_tokens()),
                )

        if best_similarity > SIMILARITY_THRESHOLD:
            return NoveltyEvaluation(
                status=NoveltyStatus.SIMILAR,
                similarity_score=round(best_similarity, 4),
                reason=(
                    f"Same technique {candidate.primary_technique} and executable "
                    f"{candidate.normalized_executable} with command similarity "
                    f"{best_similarity:.3f} > {SIMILARITY_THRESHOLD:.2f}."
                ),
                fingerprint=candidate,
            )

        return NoveltyEvaluation(
            status=NoveltyStatus.NOVEL,
            similarity_score=round(best_similarity, 4),
            reason="No matching technique/executable pattern in prior strategy history.",
            fingerprint=candidate,
        )


def _normalize_command(executable: str, arguments: List[str]) -> str:
    """Canonical command representation for fingerprinting.

    Strips whitespace so cosmetic differences ("whoami " vs "whoami") collapse
    onto the same canonical form and are flagged as SIMILAR/DUPLICATE.
    """
    cleaned_args = [re.sub(r"\s+", " ", arg).strip() for arg in arguments if arg]
    return f"{executable}:{' '.join(cleaned_args)}"


def _token_jaccard(a: List[str], b: List[str]) -> float:
    """Jaccard similarity over token sets (deduplicated)."""
    set_a = {t for t in a if t}
    set_b = {t for t in b if t}
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 0.0
    intersection = set_a & set_b
    return len(intersection) / len(union)