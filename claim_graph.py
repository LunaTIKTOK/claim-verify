"""Structured claim graph primitives and deterministic builders.

This module converts raw claim text into persistent, machine-readable claim
objects that downstream modules can consume without relying on ephemeral
string-only intermediates.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Callable

MIN_ATOMIC_CHARS = 12


@dataclass
class Entity:
    name: str
    type: str = "unknown"


@dataclass
class AtomicClaim:
    id: str
    text: str
    normalized_text: str
    independently_testable: bool = True


@dataclass
class Assumption:
    id: str
    text: str
    action_family: str
    testability: str
    confidence: float
    failure_cost: str


@dataclass
class EvidenceNeed:
    type: str
    description: str
    priority_score: float


@dataclass
class Claim:
    id: str
    original_text: str
    normalized_text: str
    claim_type: str
    time_scope: str | None
    entities: list[Entity] = field(default_factory=list)
    atomic_claims: list[AtomicClaim] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    required_evidence: list[EvidenceNeed] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    falsifiers: list[str] = field(default_factory=list)
    confidence: float = 0.5
    priority: float = 0.5

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _deterministic_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{digest}"


def _looks_testable(text: str) -> bool:
    lowered = text.lower()
    verbs = (
        " is ", " are ", " will ", " can ", " should ", " has ", " have ",
        " increase", " decrease", " dominate", " lead", " replace", " improve",
        " requires", " depends",
    )
    return len(text) >= MIN_ATOMIC_CHARS and any(token in f" {lowered} " for token in verbs)


def decompose_claim(claim_text: str) -> list[AtomicClaim]:
    """Split claim text into de-duplicated independently testable atomic claims."""
    normalized = normalize_text(claim_text)
    pieces = re.split(r"\band\b|\bbecause\b|,|;", normalized, flags=re.IGNORECASE)

    seen: set[str] = set()
    atomic: list[AtomicClaim] = []
    for piece in pieces:
        cleaned = normalize_text(piece.strip(" ."))
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        if len(cleaned) < MIN_ATOMIC_CHARS:
            continue
        if not _looks_testable(cleaned):
            continue
        seen.add(key)
        atomic.append(
            AtomicClaim(
                id=_deterministic_id("atomic", cleaned),
                text=cleaned,
                normalized_text=cleaned.lower(),
                independently_testable=True,
            )
        )

    if not atomic and normalized:
        fallback = normalized.strip(" .")
        atomic.append(
            AtomicClaim(
                id=_deterministic_id("atomic", fallback),
                text=fallback,
                normalized_text=fallback.lower(),
                independently_testable=_looks_testable(fallback),
            )
        )
    return atomic


def _infer_entity_type(name: str) -> str:
    lowered = name.lower()
    if any(token in lowered for token in ("inc", "corp", "llc", "coinbase", "openai", "google", "microsoft")):
        return "company"
    if any(token in lowered for token in ("api", "model", "system", "engine", "platform", "layer")):
        return "system"
    if any(token in lowered for token in ("rate", "latency", "accuracy", "precision", "recall", "cost", "revenue", "margin", "tokens")):
        return "metric"
    return "unknown"


def extract_entities(text: str) -> list[Entity]:
    """Extract entities using deterministic heuristics (no external NLP)."""
    normalized = normalize_text(text)
    candidates: list[str] = []

    for match in re.finditer(r"\b([A-Z][A-Za-z0-9]*(?:\s+[A-Z][A-Za-z0-9]*)*)\b", normalized):
        phrase = normalize_text(match.group(1))
        if len(phrase) >= 2:
            candidates.append(phrase)

    keyword_patterns = [
        r"\b[A-Za-z0-9_-]+\s+API\b",
        r"\b[A-Za-z0-9_-]+\s+model\b",
        r"\b[A-Za-z0-9_-]+\s+system\b",
        r"\btoken[s]?\b",
    ]
    for pattern in keyword_patterns:
        for match in re.finditer(pattern, normalized, flags=re.IGNORECASE):
            candidates.append(normalize_text(match.group(0)))

    seen: set[str] = set()
    entities: list[Entity] = []
    for candidate in candidates:
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        entities.append(Entity(name=candidate, type=_infer_entity_type(candidate)))
    return entities


def infer_evidence_needs(claim: Claim) -> list[EvidenceNeed]:
    """Infer evidence requirements from claim type + structured assumptions."""
    needs: list[EvidenceNeed] = []

    def add_need(kind: str, description: str, score: float) -> None:
        needs.append(EvidenceNeed(type=kind, description=description, priority_score=score))

    families = {assumption.action_family for assumption in claim.assumptions}
    if "dominance" in families or "comparison" in families or claim.claim_type == "comparative":
        add_need("comparison", "Baseline comparison against strongest alternatives", 0.9)
    if "causation" in families:
        add_need("validation", "Dependency validation proving causal linkage", 0.95)
    if "dependency" in families:
        add_need("constraint_check", "Prerequisite and dependency constraint validation", 0.85)
    if any(f in families for f in {"growth", "optimization", "persistence"}):
        add_need("metric", "Time-series metric checkpoints for trend persistence", 0.8)

    if claim.claim_type in {"forward_looking", "predictive"}:
        add_need("validation", "Forward-looking checkpoint with explicit timeframe", 0.75)

    if not needs:
        add_need("metric", "Observable metric that can confirm or falsify the claim", 0.6)

    dedup: list[EvidenceNeed] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(needs, key=lambda x: x.priority_score, reverse=True):
        key = (item.type, item.description.lower())
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)
    return dedup


def _infer_time_scope(text: str) -> str | None:
    lowered = text.lower()
    if any(token in lowered for token in ("will", "going to", "next", "future", "by ")):
        return "forward_looking"
    if any(token in lowered for token in ("currently", "today", "now", "is", "are")):
        return "present"
    return None


def _default_acceptance_criteria(atomic_claims: list[AtomicClaim]) -> list[str]:
    criteria = [f"Evidence confirms atomic claim: {item.text}" for item in atomic_claims[:3]]
    return criteria or ["At least one independently verifiable metric supports the claim"]


def _default_falsifiers(atomic_claims: list[AtomicClaim]) -> list[str]:
    falsifiers = [f"Contradictory evidence falsifies: {item.text}" for item in atomic_claims[:3]]
    return falsifiers or ["A direct counterexample invalidates the claim"]


def build_claim_graph(
    text: str,
    *,
    claim_type: str = "interpretive",
    infer_action_family_fn: Callable[[str], str] | None = None,
    price_assumption_failure_fn: Callable[..., dict] | None = None,
    extract_assumptions_fn: Callable[[str], list[str]] | None = None,
    action_type: str = "reversible",
    toxicity_risk: str = "medium",
    reasoning_contamination_risk: str = "medium",
    evidence_strength: str = "none",
) -> Claim:
    """Build a deterministic structured claim graph from raw text."""
    original = normalize_text(text)
    normalized = original.lower()

    if infer_action_family_fn is None or price_assumption_failure_fn is None or extract_assumptions_fn is None:
        # Import lazily to avoid circular imports.
        from verify import extract_assumptions, infer_action_family, price_assumption_failure

        infer_action_family_fn = infer_action_family_fn or infer_action_family
        price_assumption_failure_fn = price_assumption_failure_fn or price_assumption_failure
        extract_assumptions_fn = extract_assumptions_fn or extract_assumptions

    atomic_claims = decompose_claim(original)
    entities = extract_entities(original)

    assumption_texts = extract_assumptions_fn(original)
    assumptions: list[Assumption] = []
    for assumption_text in assumption_texts:
        priced = price_assumption_failure_fn(
            assumption_text,
            action_type=action_type,
            toxicity_risk=toxicity_risk,
            reasoning_contamination_risk=reasoning_contamination_risk,
            evidence_strength=evidence_strength,
        )
        assumptions.append(
            Assumption(
                id=_deterministic_id("asm", assumption_text),
                text=normalize_text(assumption_text),
                action_family=infer_action_family_fn(assumption_text),
                testability=str(priced.get("testability", "medium")),
                confidence=float(priced.get("confidence", 0.5)),
                failure_cost=str(priced.get("failure_cost", "medium")),
            )
        )

    claim = Claim(
        id=_deterministic_id("claim", original),
        original_text=original,
        normalized_text=normalized,
        claim_type=claim_type,
        time_scope=_infer_time_scope(original),
        entities=entities,
        atomic_claims=atomic_claims,
        assumptions=assumptions,
        required_evidence=[],
        acceptance_criteria=_default_acceptance_criteria(atomic_claims),
        falsifiers=_default_falsifiers(atomic_claims),
        confidence=0.55,
        priority=0.5,
    )
    claim.required_evidence = infer_evidence_needs(claim)
    return claim
