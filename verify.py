"""Claim triage and verification report CLI.

Features:
- Prints structured claim triage reports.
- Supports built-in sample claims or loading claim objects from JSON via --input.
- Normalizes and auto-infers triage fields when input omits them.
- Supports agent-ready JSON output via --json.
- Uses only lightweight text heuristics (no external APIs).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPORT_WIDTH = 72
PLACEHOLDER_TEXT = "None provided"

ALLOWED_CLAIM_TYPES = {
    "factual",
    "forward_looking",
    "opinion",
    "non_falsifiable",
    "interpretive",
}
ALLOWED_TRUTH_STATUS = {"true", "mixed", "false", "unknown", "unsupported", "structurally_invalid"}
ALLOWED_EVIDENCE_STRENGTH = {"strong", "moderate", "weak", "none"}
ALLOWED_BULLSHIT_RISK = {"low", "medium", "high", "very_high"}
ALLOWED_ACTION_STATUS = {
    "safe_to_act",
    "use_with_caution",
    "monitor_only",
    "do_not_act",
}

FORWARD_LOOKING_TERMS = (" will ", " going to ", " expected ", " likely ")
OPINION_TERMS = (" should ", " best ", " worst ", " better ")
ABSOLUTE_TERMS = (
    " always ",
    " never ",
    " all ",
    " none ",
    " guaranteed ",
    " obvious ",
    " massive ",
    " huge ",
)

ENGLISH_MARKERS = {
    "the",
    "and",
    "will",
    "is",
    "are",
    "for",
    "with",
    "because",
    "likely",
}
NON_ENGLISH_HINTS = (
    " el ",
    " la ",
    " los ",
    " las ",
    " de ",
    " para ",
    " y ",
    " será ",
    " sera ",
    " le ",
    " les ",
    " des ",
    " pour ",
    " et ",
    " deviendra ",
)
STATIC_TRANSLATIONS = {
    "coinbase dominará los pagos de agentes y usdc se convertirá en la capa principal de liquidación para agentes de ia": "Coinbase will dominate agent payments and USDC will become the primary settlement layer for AI agents",
    "coinbase dominera les paiements d'agents et usdc deviendra la principale couche de règlement pour les agents ia": "Coinbase will dominate agent payments and USDC will become the primary settlement layer for AI agents",
}


@dataclass
class ClaimReport:
    """Structured claim triage record."""

    claim: str
    original_claim: str = ""
    analysis_claim: str = ""
    language_detected: str = "english"
    translation_used: bool = False
    claim_type: str = "interpretive"
    truth_status: str = "unknown"
    evidence_strength: str = "none"
    bullshit_risk: str = "medium"
    action_status: str = "monitor_only"
    rewrite_required: bool = False
    sources: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    interpretation: str = ""
    bottom_line: str = ""
    next_step: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClaimReport":
        """Build a normalized + inferred ClaimReport from dictionary data."""
        claim = clean_text(data.get("claim"), fallback="No claim provided")
        language_data = normalize_claim_language(claim)
        original_claim = language_data["original_claim"]
        analysis_claim = language_data["analysis_claim"]
        language_detected = language_data["language_detected"]
        translation_used = bool(language_data["translation_used"])
        sources = clean_list(data.get("sources"))
        facts = clean_list(data.get("facts"))
        gaps = clean_list(data.get("gaps"))

        verdict = clean_text(data.get("verdict"), fallback="")

        claim_type = (
            normalize_claim_type(data.get("claim_type"))
            if has_user_value(data.get("claim_type"))
            else infer_claim_type(analysis_claim)
        )
        truth_status = (
            normalize_truth_status(data.get("truth_status"))
            if has_user_value(data.get("truth_status"))
            else infer_truth_status(verdict)
        )
        evidence_strength = (
            normalize_evidence_strength(data.get("evidence_strength"))
            if has_user_value(data.get("evidence_strength"))
            else infer_evidence_strength(sources, facts, gaps)
        )
        bullshit_risk = (
            normalize_bullshit_risk(data.get("bullshit_risk"))
            if has_user_value(data.get("bullshit_risk"))
            else infer_bullshit_risk(analysis_claim, gaps, sources)
        )
        rewrite_required = (
            normalize_rewrite_required(data.get("rewrite_required"))
            if has_user_value(data.get("rewrite_required"))
            else infer_rewrite_required(analysis_claim)
        )
        action_status = (
            normalize_action_status(data.get("action_status"))
            if has_user_value(data.get("action_status"))
            else infer_action_status(truth_status, evidence_strength, bullshit_risk)
        )

        return cls(
            claim=original_claim,
            original_claim=original_claim,
            analysis_claim=analysis_claim,
            language_detected=language_detected,
            translation_used=translation_used,
            claim_type=claim_type,
            truth_status=truth_status,
            evidence_strength=evidence_strength,
            bullshit_risk=bullshit_risk,
            action_status=action_status,
            rewrite_required=rewrite_required,
            sources=sources,
            facts=facts,
            gaps=gaps,
            interpretation=clean_text(data.get("interpretation"), fallback=""),
            bottom_line=clean_text(data.get("bottom_line"), fallback=""),
            next_step=clean_text(data.get("next_step"), fallback=""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return structured agent-ready JSON output."""
        structural_validity = infer_structural_validity(self.analysis_claim)

        truth_status = self.truth_status
        if truth_status == "unknown" and contradicts_known_constraints(self.analysis_claim):
            truth_status = "structurally_invalid"
            structural_validity = "invalid"

        bullshit_risk = self.bullshit_risk
        decision_risk = infer_decision_risk(
            truth_status=truth_status,
            evidence_strength=self.evidence_strength,
            bullshit_risk=bullshit_risk,
        )
        confidence = infer_confidence(
            evidence_strength=self.evidence_strength,
            truth_status=truth_status,
            bullshit_risk=bullshit_risk,
            structural_validity=structural_validity,
        )
        rewritten_claims = rewrite_claim(self.analysis_claim, self.rewrite_required)
        priority_score = infer_priority_score(
            decision_risk=decision_risk,
            evidence_strength=self.evidence_strength,
            bullshit_risk=bullshit_risk,
            truth_status=truth_status,
        )
        verification_priority = infer_verification_priority(priority_score)
        expected_error_cost = infer_expected_error_cost(
            truth_status=truth_status,
            evidence_strength=self.evidence_strength,
            bullshit_risk=bullshit_risk,
            decision_risk=decision_risk,
        )
        token_waste_risk = infer_token_waste_risk(
            evidence_strength=self.evidence_strength,
            rewrite_required=self.rewrite_required,
            bullshit_risk=bullshit_risk,
        )
        failure_mode = infer_failure_mode(
            claim=self.analysis_claim,
            truth_status=truth_status,
            evidence_strength=self.evidence_strength,
            rewrite_required=self.rewrite_required,
            bullshit_risk=bullshit_risk,
        )
        execution_permission = infer_execution_permission(
            report=self,
            decision_risk=decision_risk,
        )
        enforcement_reason = infer_enforcement_reason(
            report=self,
            decision_risk=decision_risk,
            expected_error_cost=expected_error_cost,
            confidence=confidence,
            execution_permission=execution_permission,
        )

        if structural_validity == "invalid":
            truth_status = "structurally_invalid"
            bullshit_risk = "very_high"
            decision_risk = "high"
            execution_permission = "block"
            enforcement_reason = "structurally invalid claim with impossible guarantees"
            expected_error_cost = "high"
            token_waste_risk = "very_high"
            failure_mode = "absolute_claim_with_impossible_constraints"
        elif structural_validity == "valid" and self.evidence_strength == "none":
            truth_status = "unsupported"
            decision_risk = "medium"
            expected_error_cost = "medium"
            execution_permission = "allow_with_warning"
            enforcement_reason = "no evidentiary grounding"
            confidence = 0.6

        bypass_simulation = simulate_bypass(
            self,
            execution_permission=execution_permission,
            structural_validity=structural_validity,
            bullshit_risk=bullshit_risk,
        )

        reason = self.bottom_line or self.interpretation or build_reason(
            truth_status,
            self.evidence_strength,
            bullshit_risk,
            self.action_status,
        )

        return {
            "claim": self.claim,
            "original_claim": self.original_claim,
            "analysis_claim": self.analysis_claim,
            "language_detected": self.language_detected,
            "translation_used": self.translation_used,
            "claim_type": self.claim_type,
            "structural_validity": structural_validity,
            "truth_status": truth_status,
            "evidence_strength": self.evidence_strength,
            "bullshit_risk": bullshit_risk,
            "decision_risk": decision_risk,
            "rewrite_required": self.rewrite_required,
            "rewritten_claims": rewritten_claims,
            "action_status": self.action_status,
            "confidence": confidence,
            "priority_score": priority_score,
            "verification_priority": verification_priority,
            "expected_error_cost": expected_error_cost,
            "token_waste_risk": token_waste_risk,
            "failure_mode": failure_mode,
            "execution_permission": execution_permission,
            "enforcement_reason": enforcement_reason,
            "bypass_simulation": bypass_simulation,
            "reason": reason,
            "next_step": self.next_step or PLACEHOLDER_TEXT,
        }

    def print_report(self) -> None:
        """Print the claim triage report."""
        payload = self.to_dict()

        print_divider()
        print_section("ORIGINAL CLAIM", text=self.original_claim)
        print_section("ANALYSIS CLAIM", text=self.analysis_claim)
        print_section("LANGUAGE DETECTED", text=self.language_detected)
        print_section("TRANSLATION USED", text=format_bool(self.translation_used))
        print_section("CLAIM TYPE", text=self.claim_type)
        print_section("STRUCTURAL VALIDITY", text=payload["structural_validity"])
        print_section("TRUTH STATUS", text=payload["truth_status"])
        print_section("EVIDENCE STRENGTH", text=self.evidence_strength)
        print_section("BULLSHIT RISK", text=payload["bullshit_risk"])
        print_section("ACTION STATUS", text=payload["action_status"])
        print_section("REWRITE REQUIRED", text=format_bool(self.rewrite_required))
        print_section("ATOMIC CLAIMS", items=payload["rewritten_claims"])
        print_section("PRIORITY SCORE", text=f"{payload['priority_score']:.2f}")
        print_section("VERIFICATION PRIORITY", text=payload["verification_priority"])
        print_section("EXPECTED ERROR COST", text=payload["expected_error_cost"])
        print_section("TOKEN WASTE RISK", text=payload["token_waste_risk"])
        print_section("FAILURE MODE", text=payload["failure_mode"])
        print_section("EXECUTION PERMISSION", text=payload["execution_permission"])
        print_section("ENFORCEMENT REASON", text=payload["enforcement_reason"])
        print_section(
            "BYPASS SIMULATION",
            items=[
                f"would_proceed: {payload['bypass_simulation']['would_proceed']}",
                f"expected_outcome: {payload['bypass_simulation']['expected_outcome']}",
                f"estimated_loss: {payload['bypass_simulation']['estimated_loss']}",
                f"compute_multiplier: {payload['bypass_simulation']['compute_multiplier']:.2f}x",
            ],
        )
        print(
            "BYPASS CONSEQUENCE: Acting without this gate is expected to increase "
            f"compute cost by {payload['bypass_simulation']['compute_multiplier']:.2f}× "
            f"and risk level to {payload['bypass_simulation']['estimated_loss']}"
        )
        print()

        print_section("SOURCES", items=self.sources)
        print_section("FACTS", items=self.facts)
        print_section("GAPS / CONTRADICTIONS", items=self.gaps)

        if self.interpretation:
            print_section("INTERPRETATION", text=self.interpretation)

        if self.bottom_line:
            print_section("BOTTOM LINE", text=self.bottom_line)

        if self.next_step:
            print_section("NEXT STEP", text=self.next_step)

        print_divider()


def has_user_value(value: Any) -> bool:
    """True when user explicitly supplied a non-empty value."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def normalize_claim_language(claim: str) -> dict[str, Any]:
    """Normalize claim language metadata for multilingual analysis."""
    original_claim = clean_text(claim, fallback="No claim provided")
    language_detected = detect_claim_language(original_claim)

    if language_detected == "english":
        return {
            "original_claim": original_claim,
            "analysis_claim": original_claim,
            "language_detected": "english",
            "translation_used": False,
        }

    translated_claim = translate_claim_to_english(original_claim)
    if translated_claim is None:
        return {
            "original_claim": original_claim,
            "analysis_claim": original_claim,
            "language_detected": "non_english_untranslated",
            "translation_used": False,
        }

    return {
        "original_claim": original_claim,
        "analysis_claim": translated_claim,
        "language_detected": "non_english",
        "translation_used": True,
    }


def detect_claim_language(claim: str) -> str:
    """Heuristically classify whether claim text is English or non-English."""
    normalized = f" {claim.strip().lower()} "
    if not normalized.strip():
        return "english"

    english_marker_count = sum(
        1 for token in re.findall(r"[a-z]+", normalized) if token in ENGLISH_MARKERS
    )
    non_english_marker_present = any(marker in normalized for marker in NON_ENGLISH_HINTS)
    non_ascii_present = any(ord(char) > 127 for char in normalized)

    if non_english_marker_present or (non_ascii_present and english_marker_count == 0):
        return "non_english"
    return "english"


def translate_claim_to_english(claim: str) -> str | None:
    """Translate known multilingual claims into English using local fallback mappings."""
    normalized = normalize_label(claim).replace("_", " ")
    return STATIC_TRANSLATIONS.get(normalized)


def normalize_label(value: Any) -> str:
    """Return a normalized lowercase label token."""
    if not isinstance(value, str):
        return ""
    return "_".join(value.strip().lower().replace("-", "_").split())


def normalize_claim_type(value: Any) -> str:
    """Normalize claim type into the allowed set."""
    token = normalize_label(value)
    alias_map = {
        "predictive": "forward_looking",
        "forecast": "forward_looking",
        "subjective": "opinion",
        "interpretation": "interpretive",
        "not_falsifiable": "non_falsifiable",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_CLAIM_TYPES else "interpretive"


def normalize_truth_status(value: Any) -> str:
    """Normalize truth status into the allowed set."""
    token = normalize_label(value)
    alias_map = {
        "verified": "true",
        "partially_verified": "mixed",
        "partly_true": "mixed",
        "unverified": "unknown",
        "unsupported": "unsupported",
        "inconclusive": "unknown",
        "invalid": "structurally_invalid",
        "structurally_invalid": "structurally_invalid",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_TRUTH_STATUS else "unknown"


def normalize_evidence_strength(value: Any) -> str:
    """Normalize evidence strength into the allowed set."""
    token = normalize_label(value)
    alias_map = {
        "very_strong": "strong",
        "medium": "moderate",
        "limited": "weak",
        "insufficient": "none",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_EVIDENCE_STRENGTH else "none"


def normalize_bullshit_risk(value: Any) -> str:
    """Normalize bullshit risk into the allowed set."""
    token = normalize_label(value)
    alias_map = {
        "minimal": "low",
        "elevated": "medium",
        "severe": "high",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_BULLSHIT_RISK else "medium"


def normalize_action_status(value: Any) -> str:
    """Normalize action status into the allowed set."""
    token = normalize_label(value)
    alias_map = {
        "act": "safe_to_act",
        "proceed": "safe_to_act",
        "caution": "use_with_caution",
        "watch": "monitor_only",
        "avoid": "do_not_act",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_ACTION_STATUS else "monitor_only"


def normalize_rewrite_required(value: Any) -> bool:
    """Normalize rewrite_required into a boolean."""
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        token = value.strip().lower()
        if token in {"true", "yes", "y", "1", "required", "rewrite"}:
            return True
        if token in {"false", "no", "n", "0", "not_required", "none"}:
            return False

    return False


def infer_claim_type(claim: str) -> str:
    """Infer claim type from claim text."""
    text = f" {claim.lower()} "
    if any(term in text for term in FORWARD_LOOKING_TERMS):
        return "forward_looking"

    if any(term in text for term in OPINION_TERMS):
        if " should " in text or " better " in text:
            return "opinion"
        return "interpretive"

    return "factual"


def infer_bullshit_risk(claim: str, gaps: list[str], sources: list[str]) -> str:
    """Infer bullshit risk from language intensity and support quality."""
    text = f" {claim.lower()} "
    score = 0
    absolute_present = any(term in text for term in ABSOLUTE_TERMS)

    if absolute_present:
        score += 2

    if infer_rewrite_required(claim):
        score += 1

    if not sources:
        score += 1

    if len(gaps) >= 2:
        score += 1

    if absolute_present and (not has_independent_sources(sources)) and is_vague_scope(claim):
        return "very_high"

    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


def infer_evidence_strength(sources: list[str], facts: list[str], gaps: list[str]) -> str:
    """Infer evidence strength from source/fact/gap balance."""
    if not sources:
        return "none"

    source_text = " | ".join(source.lower() for source in sources)
    weak_source_markers = ("vendor", "press release", "no independent", "keynote")
    has_weak_markers = any(marker in source_text for marker in weak_source_markers)

    if not has_independent_sources(sources):
        return "none"

    if has_weak_markers:
        return "weak"

    contradiction_like = sum(
        1
        for gap in gaps
        if any(
            token in gap.lower()
            for token in ("contradict", "conflict", "inconsistent", "unclear", "missing")
        )
    )

    if contradiction_like >= 2 or len(gaps) > len(facts):
        return "weak"

    if len(sources) >= 2 and len(facts) >= 2 and len(gaps) == 0:
        return "strong"

    return "moderate"


def infer_truth_status(verdict: str) -> str:
    """Infer truth status from a verdict-like input."""
    token = normalize_label(verdict)
    if token in {"true", "verified", "supported"}:
        return "true"
    if token in {"mixed", "partially_verified", "partly_true", "partially_supported"}:
        return "mixed"
    if token in {"false", "refuted", "unsupported"}:
        return "false"
    return "unknown"


def infer_action_status(truth_status: str, evidence_strength: str, bullshit_risk: str) -> str:
    """Infer action status from truth/evidence/risk state."""
    if truth_status == "true" and evidence_strength == "strong":
        return "safe_to_act"
    if truth_status == "mixed":
        return "use_with_caution"
    if truth_status == "unknown" and bullshit_risk == "high":
        return "do_not_act"
    if truth_status == "unknown" and evidence_strength == "moderate":
        return "monitor_only"
    if truth_status == "false":
        return "do_not_act"
    return "monitor_only"


def infer_decision_risk(truth_status: str, evidence_strength: str, bullshit_risk: str) -> str:
    """Infer decision risk level."""
    if bullshit_risk in {"high", "very_high"} or truth_status == "unknown":
        return "high"
    if truth_status == "true" and evidence_strength == "strong":
        return "low"
    if evidence_strength == "moderate":
        return "medium"
    return "medium"


def infer_confidence(
    evidence_strength: str,
    truth_status: str,
    bullshit_risk: str,
    structural_validity: str,
) -> float:
    """Infer confidence-in-classification score in range [0.0, 1.0]."""
    if structural_validity == "invalid":
        return 0.9
    if truth_status == "unsupported":
        return 0.6

    score = 0.5

    if evidence_strength == "strong":
        score += 0.3
    elif evidence_strength == "moderate":
        score += 0.1

    if bullshit_risk == "high":
        score -= 0.3

    if truth_status == "unknown":
        score -= 0.2

    if bullshit_risk == "very_high":
        score = max(score, 0.8)

    return max(0.0, min(1.0, round(score, 2)))


def infer_priority_score(
    decision_risk: str,
    evidence_strength: str,
    bullshit_risk: str,
    truth_status: str,
) -> float:
    """Infer verification priority score in range [0.0, 1.0]."""
    score = 0.5

    if decision_risk == "high":
        score += 0.2

    if evidence_strength in {"weak", "none"}:
        score += 0.2

    if bullshit_risk == "high":
        score += 0.1

    if truth_status == "true" and evidence_strength == "strong":
        score -= 0.2

    return max(0.0, min(1.0, round(score, 2)))


def infer_verification_priority(priority_score: float) -> str:
    """Map priority score to a priority bucket."""
    if priority_score >= 0.7:
        return "high"
    if priority_score >= 0.4:
        return "medium"
    return "low"


def infer_expected_error_cost(
    truth_status: str,
    evidence_strength: str,
    bullshit_risk: str,
    decision_risk: str,
) -> str:
    """Infer expected error cost as low/medium/high."""
    if (
        bullshit_risk == "high"
        or truth_status == "unknown"
        or decision_risk == "high"
    ):
        return "high"

    if truth_status == "mixed" or evidence_strength == "moderate":
        return "medium"

    if (
        truth_status == "true"
        and evidence_strength == "strong"
        and bullshit_risk == "low"
    ):
        return "low"

    return "medium"


def infer_token_waste_risk(
    evidence_strength: str,
    rewrite_required: bool,
    bullshit_risk: str,
) -> str:
    """Infer likely token waste from claim quality and structure."""
    if bullshit_risk == "very_high":
        return "very_high"

    if evidence_strength in {"weak", "none"} and rewrite_required:
        return "high"

    if evidence_strength == "moderate" or rewrite_required:
        return "medium"

    if evidence_strength == "strong" and not rewrite_required:
        return "low"

    if bullshit_risk == "high":
        return "medium"

    return "medium"


def infer_failure_mode(
    claim: str,
    truth_status: str,
    evidence_strength: str,
    rewrite_required: bool,
    bullshit_risk: str,
) -> str:
    """Infer concise likely failure mode."""
    if rewrite_required:
        return "compound claim risk"

    if truth_status == "unknown" and bullshit_risk == "high":
        return "acting on weak unreliable claim"

    if evidence_strength == "none":
        return "no evidentiary grounding"

    if truth_status == "mixed":
        return "partial support misread as certainty"

    if infer_claim_type(claim) == "forward_looking":
        return "forecast uncertainty"

    return "context mismatch risk"


def has_absolute_language(claim: str) -> bool:
    """Check whether claim uses absolute guarantee-like language."""
    text = f" {claim.lower()} "
    return any(term in text for term in (" all ", " always ", " never ", " guarantee ", " guaranteed ", " zero "))


def has_measurable_scope_or_constraints(claim: str) -> bool:
    """Check for simple measurable constraints/scoping language."""
    text = claim.lower()
    has_number_or_metric = bool(re.search(r"\b\d+(\.\d+)?\b|%|p\d{2}|ms|seconds?|days?|years?", text))
    has_scope_token = any(token in text for token in ("in ", "for ", "under ", "within ", "at ", "on "))
    return has_number_or_metric and has_scope_token


def is_vague_scope(claim: str) -> bool:
    """True when claim lacks clear measurable constraints."""
    return not has_measurable_scope_or_constraints(claim)


def has_independent_sources(sources: list[str]) -> bool:
    """Heuristic check for independent/audited source signals."""
    indicators = ("independent", "third-party", "peer-reviewed", "official", "audited")
    for source in sources:
        text = source.lower()
        if "no independent" in text:
            continue
        if any(ind in text for ind in indicators):
            return True
    return False


def infer_structural_validity(claim: str) -> str:
    """Infer structural validity as valid/invalid."""
    if has_absolute_language(claim) and is_vague_scope(claim):
        return "invalid"
    return "valid"


def contradicts_known_constraints(claim: str) -> bool:
    """Detect claims that contradict basic system constraints."""
    text = claim.lower()
    impossible_patterns = (
        "eliminate all",
        "zero downtime across every",
        "never make mistakes",
        "guaranteed zero",
        "always correct",
    )
    return any(pattern in text for pattern in impossible_patterns)


def should_block_action(report: ClaimReport) -> bool:
    """Return True when enforcement must block action."""
    decision_risk = infer_decision_risk(
        truth_status=report.truth_status,
        evidence_strength=report.evidence_strength,
        bullshit_risk=report.bullshit_risk,
    )
    expected_error_cost = infer_expected_error_cost(
        truth_status=report.truth_status,
        evidence_strength=report.evidence_strength,
        bullshit_risk=report.bullshit_risk,
        decision_risk=decision_risk,
    )
    confidence = infer_confidence(
        evidence_strength=report.evidence_strength,
        truth_status=report.truth_status,
        bullshit_risk=report.bullshit_risk,
        structural_validity=infer_structural_validity(report.analysis_claim),
    )

    return (
        report.action_status == "do_not_act"
        or (expected_error_cost == "high" and confidence < 0.5)
        or (report.bullshit_risk in {"high", "very_high"} and report.truth_status == "unknown")
    )


def infer_execution_permission(report: ClaimReport, decision_risk: str) -> str:
    """Infer execution permission level for pre-action gate."""
    if should_block_action(report):
        return "block"

    if report.action_status == "safe_to_act":
        return "allow"

    if report.action_status == "use_with_caution" or decision_risk == "medium":
        return "allow_with_warning"

    return "allow_with_warning"


def infer_enforcement_reason(
    report: ClaimReport,
    decision_risk: str,
    expected_error_cost: str,
    confidence: float,
    execution_permission: str,
) -> str:
    """Infer concise reason for enforcement decision."""
    if execution_permission == "block":
        if report.action_status == "do_not_act":
            return "explicit do_not_act gate"
        if expected_error_cost == "high" and confidence < 0.5:
            return "high expected error cost"
        if report.bullshit_risk == "high" and report.truth_status == "unknown":
            return "compound claim with high ambiguity"
        return "low confidence and weak evidence"

    if execution_permission == "allow_with_warning":
        if report.action_status == "use_with_caution":
            return "action marked use_with_caution"
        if decision_risk == "medium":
            return "medium decision risk"
        return "partial uncertainty remains"

    return "sufficient evidence for execution"


def simulate_bypass(
    report: ClaimReport,
    execution_permission: str | None = None,
    structural_validity: str | None = None,
    bullshit_risk: str | None = None,
) -> dict[str, Any]:
    """Simulate likely consequence of bypassing the pre-action gate."""
    decision_risk = infer_decision_risk(
        truth_status=report.truth_status,
        evidence_strength=report.evidence_strength,
        bullshit_risk=report.bullshit_risk,
    )
    permission = execution_permission or infer_execution_permission(report, decision_risk)
    validity = structural_validity or infer_structural_validity(report.analysis_claim)
    risk = bullshit_risk or report.bullshit_risk

    if permission == "block":
        multiplier = 5.0
        if validity == "invalid":
            multiplier = 6.0
        if validity == "invalid" and risk == "very_high":
            multiplier = 8.0
        return {
            "would_proceed": True,
            "expected_outcome": "high likelihood of incorrect action",
            "estimated_loss": "high",
            "compute_multiplier": multiplier,
        }

    if permission == "allow_with_warning":
        return {
            "would_proceed": True,
            "expected_outcome": "moderate uncertainty, potential inefficiency",
            "estimated_loss": "medium",
            "compute_multiplier": 2.0,
        }

    return {
        "would_proceed": True,
        "expected_outcome": "low risk, efficient execution",
        "estimated_loss": "low",
        "compute_multiplier": 1.1,
    }


def infer_rewrite_required(claim: str) -> bool:
    """Infer whether claim should be rewritten for clarity/testability."""
    text = claim.lower()
    separator_count = text.count(" and ") + text.count(" because ") + text.count(";") + text.count(",")
    return separator_count >= 1


def extract_atomic_claims(claim: str) -> list[str]:
    """Extract cleaned, de-duplicated, meaningful atomic claims."""
    pieces = re.split(r"\band\b|\bbecause\b|,|;", claim, flags=re.IGNORECASE)

    seen: set[str] = set()
    atomic: list[str] = []
    for piece in pieces:
        cleaned = piece.strip(" .")
        if len(cleaned) <= 5:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        atomic.append(cleaned)

    return atomic


def extract_claims_from_text(text: str) -> list[str]:
    """Extract unique, meaningful claim candidates from raw text input."""
    parts = re.split(r"\.|,|\band\b|\bbecause\b", text, flags=re.IGNORECASE)

    seen: set[str] = set()
    claims: list[str] = []
    for part in parts:
        cleaned = part.strip(" \n\t.;:")
        if len(cleaned) < 8:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        claims.append(cleaned)
    return claims


def rewrite_claim(claim: str, rewrite_required: bool) -> list[str]:
    """Return decomposed subclaims when possible, otherwise original claim."""
    atomic = extract_atomic_claims(claim) if rewrite_required else []
    return atomic if len(atomic) > 1 else [clean_text(claim)]


def rewrite_claims(claim: str, rewrite_required: bool) -> list[str]:
    """Backward-compatible wrapper for claim rewrite/decomposition."""
    return rewrite_claim(claim, rewrite_required)


def build_reason(truth_status: str, evidence_strength: str, bullshit_risk: str, action_status: str) -> str:
    """Build a compact model reason string for agent output."""
    return (
        f"truth_status={truth_status}, evidence_strength={evidence_strength}, "
        f"bullshit_risk={bullshit_risk}, action_status={action_status}."
    )


def clean_list(items: Any) -> list[str]:
    """Convert input to a clean list of non-empty strings."""
    if items is None:
        return []

    if isinstance(items, str):
        items = [items]

    if not isinstance(items, Iterable):
        return []

    cleaned: list[str] = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            cleaned.append(text)
    return cleaned


def clean_text(value: Any, fallback: str = PLACEHOLDER_TEXT) -> str:
    """Convert any value to stripped text with a fallback."""
    if value is None:
        return fallback

    text = str(value).strip()
    return text if text else fallback


def format_bool(value: bool) -> str:
    """Format boolean as an explicit lower-case token."""
    return "true" if value else "false"


def print_divider(char: str = "=") -> None:
    """Print a report divider."""
    print(char * REPORT_WIDTH)


def print_section(title: str, items: list[str] | None = None, text: str | None = None) -> None:
    """Print a formatted report section."""
    print(title)
    print("-" * REPORT_WIDTH)

    if text is not None:
        print(clean_text(text))
        print()
        return

    if items:
        for item in items:
            print(f"- {item}")
    else:
        print(PLACEHOLDER_TEXT)
    print()


def verify_claim(claim: str) -> None:
    """Print a basic triage report for a single claim string."""
    report = ClaimReport.from_dict({"claim": claim})
    report.print_report()


def evaluate_text(text: str) -> list[dict[str, Any]]:
    """Evaluate raw text by extracting candidate claims and returning JSON-ready reports."""
    raw_claims = extract_claims_from_text(text)
    claims = [ClaimReport.from_dict({"claim": claim}) for claim in raw_claims]
    return [claim.to_dict() for claim in claims]


def evaluate_claim(claim: str) -> dict[str, Any]:
    """Evaluate one claim string and return a JSON-ready report dictionary."""
    report = ClaimReport.from_dict({"claim": claim})
    return report.to_dict()


def validate_claim_entry(entry: Any, index: int) -> dict[str, Any]:
    """Validate one JSON claim entry and return it as a dictionary."""
    if not isinstance(entry, dict):
        raise SystemExit(
            f"Error: claim at index {index} is {type(entry).__name__}, expected an object."
        )

    missing = [field for field in ("claim",) if field not in entry]
    if missing:
        raise SystemExit(
            f"Error: claim at index {index} is missing required field(s): {', '.join(missing)}."
        )

    return entry


def load_claims_from_json(path: Path) -> list[ClaimReport]:
    """Load claim reports from a JSON file."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        raise SystemExit(f"Error: file not found: {path}")
    except PermissionError:
        raise SystemExit(f"Error: permission denied reading file: {path}")
    except OSError as exc:
        raise SystemExit(f"Error: could not read file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Error: invalid JSON in {path}: {exc}") from exc

    if not isinstance(raw, list):
        raise SystemExit("Error: JSON root must be a list of claim objects.")

    claims: list[ClaimReport] = []
    for index, item in enumerate(raw):
        valid_item = validate_claim_entry(item, index)
        claims.append(ClaimReport.from_dict(valid_item))

    return claims


def get_sample_claims() -> list[ClaimReport]:
    """Return built-in realistic sample claim reports with varied risk levels."""
    sample_data = [
        {
            "claim": "AI copilots will replace all engineers and guaranteed huge productivity gains because they never make mistakes.",
            "sources": ["Mixed benchmark reports across teams"],
            "facts": ["Productivity gains vary by task and require review."],
            "gaps": [
                "Contains absolute words and broad universal claims.",
                "Multiple causal assertions are bundled into one statement.",
            ],
            "truth_status": "unknown",
            "next_step": "Split into measurable subclaims and validate each with controlled benchmarks.",
        },
        {
            "claim": "Switching incident postmortems to blameless templates reduced repeat Sev-1 incidents by 28 percent last quarter.",
            "sources": [
                "Internal incident tracker export",
                "Quarterly reliability review",
                "Postmortem process changelog",
            ],
            "facts": [
                "Repeat Sev-1 count dropped from 18 to 13.",
                "Template adoption reached 95 percent of incidents.",
                "No simultaneous major process change was recorded.",
            ],
            "gaps": [],
            "truth_status": "true",
            "evidence_strength": "strong",
            "next_step": "Replicate this process in adjacent teams and monitor quarterly.",
        },
        {
            "claim": "The new model is better and cheaper, because it uses fewer GPUs, and inference latency is lower in production.",
            "sources": [
                "Internal benchmark dashboard",
                "Cloud cost report",
            ],
            "facts": [
                "Observed lower p95 latency on matched workloads.",
                "Observed lower monthly GPU spend in staging and production.",
            ],
            "gaps": ["Need independent replication on broader workload mix."],
            "truth_status": "mixed",
            "next_step": "Validate each decomposed subclaim separately over the next release cycle.",
        },
        {
            "claim": "Coinbase dominará los pagos de agentes y USDC se convertirá en la capa principal de liquidación para agentes de IA",
            "sources": [],
            "facts": [],
            "gaps": [],
            "truth_status": "unknown",
            "next_step": "Translate and validate each subclaim with independent adoption metrics.",
        },
        {
            "claim": "Coinbase dominera les paiements d'agents et USDC deviendra la principale couche de règlement pour les agents IA",
            "sources": [],
            "facts": [],
            "gaps": [],
            "truth_status": "unknown",
            "next_step": "Translate and validate each subclaim with audited market-share and settlement-volume data.",
        },
    ]
    return [ClaimReport.from_dict(item) for item in sample_data]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Print structured claim triage reports.")
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to a JSON file containing claim objects.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full reports as structured JSON instead of terminal text.",
    )
    parser.add_argument(
        "--text_input",
        type=str,
        help="Raw text input to auto-extract claim candidates and evaluate them.",
    )
    return parser.parse_args()


def main() -> int:
    """Entry point for the CLI."""
    args = parse_args()

    if args.text_input is not None:
        raw_claims = extract_claims_from_text(args.text_input)
        claims = [ClaimReport.from_dict({"claim": claim}) for claim in raw_claims]
    elif args.input is not None:
        claims = load_claims_from_json(args.input)
    else:
        claims = get_sample_claims()

    if args.json:
        payload = [claim.to_dict() for claim in claims]
        print(json.dumps(payload, indent=2))
        return 0

    for index, claim in enumerate(claims, start=1):
        print(f"REPORT {index}")
        claim.print_report()
        if index != len(claims):
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
