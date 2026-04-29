"""Constraint Engine: pre-action decision system.

Evaluates whether an input should be acted on under uncertainty,
and determines how much to commit based on expected value, confidence,
and risk constraints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from claim_graph import build_claim_graph, decompose_claim

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
ALLOWED_RISK_PROFILES = {"strict", "balanced", "speculative"}
ALLOWED_ACTION_TYPES = {"reversible", "costly", "external_facing", "irreversible"}
ALLOWED_TOXICITY_RISK = {"low", "medium", "high", "critical"}

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
    risk_profile: str = "balanced"
    action_type: str = "reversible"
    base_tokens: int = 4000
    model_price: float = 0.000003
    toxicity_risk: str = "medium"
    reasoning_contamination_risk: str = "medium"
    expected_benefit: float = 0.0
    benefit_confidence: float = 0.0
    opportunity_cost_of_inaction: float = 0.0
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
    claim_graph: Any = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClaimReport":
        """Build a normalized + inferred ClaimReport from dictionary data."""
        claim = clean_text(data.get("claim"), fallback="No claim provided")
        short_circuit = structural_short_circuit(claim)
        language_data = normalize_claim_language(claim)
        original_claim = language_data["original_claim"]
        analysis_claim = language_data["analysis_claim"]
        language_detected = language_data["language_detected"]
        translation_used = bool(language_data["translation_used"])
        risk_profile = normalize_risk_profile(data.get("risk_profile"))
        action_type = normalize_action_type(data.get("action_type"))
        base_tokens = int(data.get("base_tokens", 4000))
        model_price = float(data.get("model_price", 0.000003))
        sources = clean_list(data.get("sources"))
        facts = clean_list(data.get("facts"))
        gaps = clean_list(data.get("gaps"))
        toxicity_risk = (
            normalize_toxicity_risk(data.get("toxicity_risk"))
            if has_user_value(data.get("toxicity_risk"))
            else infer_toxicity_risk(analysis_claim, gaps, action_type)
        )
        reasoning_contamination_risk = (
            normalize_toxicity_risk(data.get("reasoning_contamination_risk"))
            if has_user_value(data.get("reasoning_contamination_risk"))
            else infer_reasoning_contamination_risk(analysis_claim, gaps, toxicity_risk)
        )
        expected_benefit = float(data.get("expected_benefit", 0.0))
        benefit_confidence = float(data.get("benefit_confidence", 0.0))
        opportunity_cost_of_inaction = float(data.get("opportunity_cost_of_inaction", 0.0))

        if short_circuit is not None:
            return cls(
                claim=original_claim,
                original_claim=original_claim,
                analysis_claim=analysis_claim,
                language_detected=language_detected,
                translation_used=translation_used,
                risk_profile=risk_profile,
                action_type=action_type,
                base_tokens=base_tokens,
                model_price=model_price,
                toxicity_risk=toxicity_risk,
                reasoning_contamination_risk=reasoning_contamination_risk,
                expected_benefit=expected_benefit,
                benefit_confidence=benefit_confidence,
                opportunity_cost_of_inaction=opportunity_cost_of_inaction,
                claim_type=short_circuit["claim_type"],
                truth_status=short_circuit["truth_status"],
                evidence_strength=short_circuit["evidence_strength"],
                bullshit_risk=short_circuit["bullshit_risk"],
                action_status=short_circuit["action_status"],
                rewrite_required=short_circuit["rewrite_required"],
                sources=sources,
                facts=facts,
                gaps=gaps,
                interpretation=clean_text(data.get("interpretation"), fallback=""),
                bottom_line=clean_text(data.get("bottom_line"), fallback=""),
                next_step=clean_text(data.get("next_step"), fallback=""),
                claim_graph=data.get("claim_graph"),
            )

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
            risk_profile=risk_profile,
            action_type=action_type,
            base_tokens=base_tokens,
            model_price=model_price,
            toxicity_risk=toxicity_risk,
            reasoning_contamination_risk=reasoning_contamination_risk,
            expected_benefit=expected_benefit,
            benefit_confidence=benefit_confidence,
            opportunity_cost_of_inaction=opportunity_cost_of_inaction,
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
            claim_graph=data.get("claim_graph"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return structured agent-ready JSON output."""
        structural_validity = infer_structural_validity(self.analysis_claim)
        risk_profile = normalize_risk_profile(self.risk_profile)

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
            risk_profile=risk_profile,
            structural_validity=structural_validity,
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
            risk_profile=risk_profile,
            structural_validity=structural_validity,
        )
        claim_graph_payload = None
        claim_graph_warnings: list[str] = []
        if self.claim_graph is not None:
            if isinstance(self.claim_graph, dict):
                claim_graph_payload = self.claim_graph
            elif hasattr(self.claim_graph, "to_dict") and callable(getattr(self.claim_graph, "to_dict")):
                claim_graph_payload = self.claim_graph.to_dict()
            else:
                raise TypeError("claim_graph must be a dict or an object implementing to_dict()")

            raw_atomic_claims = claim_graph_payload.get("atomic_claims", [])
            if not isinstance(raw_atomic_claims, list):
                claim_graph_warnings.append("claim_graph fallback: atomic_claims must be a list")
            else:
                for index, item in enumerate(raw_atomic_claims):
                    if not isinstance(item, dict):
                        claim_graph_warnings.append(f"claim_graph fallback: atomic_claims[{index}] must be an object")
                        break
                    if "text" not in item:
                        claim_graph_warnings.append(f"claim_graph fallback: atomic_claims[{index}] missing key(s): text")
                        break

            raw_assumptions = claim_graph_payload.get("assumptions", [])
            if not isinstance(raw_assumptions, list):
                claim_graph_warnings.append("claim_graph fallback: assumptions must be a list")
            else:
                required_assumption_keys = {"text", "confidence", "failure_cost", "testability", "action_family"}
                for index, item in enumerate(raw_assumptions):
                    if not isinstance(item, dict):
                        claim_graph_warnings.append(f"claim_graph fallback: assumptions[{index}] must be an object")
                        break
                    missing = sorted(required_assumption_keys - set(item.keys()))
                    if missing:
                        claim_graph_warnings.append(
                            f"claim_graph fallback: assumptions[{index}] missing key(s): {', '.join(missing)}"
                        )
                        break

            if not claim_graph_warnings:
                rewritten_claims = [item["text"] for item in claim_graph_payload.get("atomic_claims", [])]
                assumptions = [item["text"] for item in raw_assumptions]
                priced_assumptions = [
                    {
                        "assumption": item["text"],
                        "confidence": item["confidence"],
                        "failure_cost": item["failure_cost"],
                        "testability": item["testability"],
                        "action_family": item["action_family"],
                    }
                    for item in raw_assumptions
                ]

        if self.claim_graph is None or claim_graph_warnings:
            assumptions = extract_assumptions(self.analysis_claim)
            priced_assumptions = [
                price_assumption_failure(
                    assumption,
                    action_type=self.action_type,
                    toxicity_risk=self.toxicity_risk,
                    reasoning_contamination_risk=self.reasoning_contamination_risk,
                    evidence_strength=self.evidence_strength,
                )
                for assumption in assumptions
            ]
        aggregate_assumption_risk = infer_aggregate_assumption_risk(
            priced_assumptions,
            evidence_strength=self.evidence_strength,
        )
        enforcement_reason = infer_enforcement_reason(
            report=self,
            decision_risk=decision_risk,
            expected_error_cost=expected_error_cost,
            confidence=confidence,
            execution_permission=execution_permission,
            risk_profile=risk_profile,
            structural_validity=structural_validity,
            assumptions=assumptions,
            aggregate_assumption_risk=aggregate_assumption_risk,
        )

        if structural_validity == "invalid":
            truth_status = "structurally_invalid"
            bullshit_risk = "very_high"
            decision_risk = "high"
            execution_permission = "consult_human"
            enforcement_reason = "consult_human: structural invalidity and no reliable independent validation"
            expected_error_cost = "high"
            token_waste_risk = "very_high"
            failure_mode = "absolute_claim_with_impossible_constraints"
        elif structural_validity == "valid" and self.evidence_strength == "none":
            truth_status = "unsupported"
            decision_risk = "medium"
            expected_error_cost = "medium"
            execution_permission = "fetch_data_then_execute"
            enforcement_reason = "unsupported claim requires evidence fetch before action"
            confidence = 0.6

        bypass_simulation = simulate_bypass(
            self,
            execution_permission=execution_permission,
            structural_validity=structural_validity,
            bullshit_risk=bullshit_risk,
            risk_profile=risk_profile,
        )
        cost_estimate = compute_action_cost_estimate(
            base_tokens=max(1, int(self.base_tokens)),
            compute_multiplier=bypass_simulation["compute_multiplier"],
            confidence=confidence,
            bullshit_risk=bullshit_risk,
            structural_validity=structural_validity,
            model_price_per_token=max(0.0, float(self.model_price)),
        )
        expected_benefit = max(0.0, float(self.expected_benefit))
        benefit_confidence = max(0.0, min(1.0, float(self.benefit_confidence)))
        opportunity_cost_of_inaction = max(0.0, float(self.opportunity_cost_of_inaction))
        expected_value = compute_expected_value(
            expected_benefit=expected_benefit,
            benefit_confidence=benefit_confidence,
            total_expected_cost_usd=cost_estimate.total_expected_cost_usd,
        )

        initial_execution_permission = execution_permission
        if structural_validity == "invalid":
            execution_permission = "consult_human"
        elif self.action_type == "irreversible" and aggregate_assumption_risk in {"high", "critical"}:
            execution_permission = "consult_human"
        elif expected_value > 0 and self.evidence_strength == "strong" and self.toxicity_risk == "low":
            execution_permission = "execute_now"
        elif expected_value > 0 and truth_status in {"unsupported", "unknown"}:
            execution_permission = "execute_with_assumptions"
        elif expected_value <= 0 and truth_status in {"unsupported", "unknown"}:
            execution_permission = "fetch_data_then_execute"
        elif expected_value <= 0:
            execution_permission = "execute_small"

        if execution_permission in {"consult_human", "hard_stop"}:
            enforcement_reason = infer_enforcement_reason(
                report=self,
                decision_risk=decision_risk,
                expected_error_cost=expected_error_cost,
                confidence=confidence,
                execution_permission=execution_permission,
                risk_profile=risk_profile,
                structural_validity=structural_validity,
                assumptions=assumptions,
                aggregate_assumption_risk=aggregate_assumption_risk,
            )

        if execution_permission != initial_execution_permission:
            bypass_simulation = simulate_bypass(
                self,
                execution_permission=execution_permission,
                structural_validity=structural_validity,
                bullshit_risk=bullshit_risk,
                risk_profile=risk_profile,
            )
            cost_estimate = compute_action_cost_estimate(
                base_tokens=max(1, int(self.base_tokens)),
                compute_multiplier=bypass_simulation["compute_multiplier"],
                confidence=confidence,
                bullshit_risk=bullshit_risk,
                structural_validity=structural_validity,
                model_price_per_token=max(0.0, float(self.model_price)),
            )
            expected_value = compute_expected_value(
                expected_benefit=expected_benefit,
                benefit_confidence=benefit_confidence,
                total_expected_cost_usd=cost_estimate.total_expected_cost_usd,
            )
        low_testability_count = sum(1 for item in priced_assumptions if item.get("testability") == "low")
        dominance_family_count = sum(1 for item in priced_assumptions if item.get("action_family") == "dominance")
        majority_low_testability = low_testability_count >= max(1, len(priced_assumptions) // 2 + 1)

        calibrated_multiplier = float(bypass_simulation["compute_multiplier"])
        calibrated_expected_loss = expected_error_cost

        if aggregate_assumption_risk == "high" and self.evidence_strength == "none" and truth_status == "unsupported":
            if calibrated_expected_loss == "medium":
                calibrated_expected_loss = "high"
            if majority_low_testability:
                calibrated_multiplier *= 1.25
            if majority_low_testability and dominance_family_count > 0:
                calibrated_multiplier *= 1.25

        penalty_if_wrong = {
            "cost_multiplier": round(calibrated_multiplier, 3),
            "expected_loss": calibrated_expected_loss,
            "expected_failure_cost_usd": {
                "low": 0.05,
                "medium": 0.2,
                "high": 0.75,
            }.get(calibrated_expected_loss, 0.2),
            "likely_failure_mode": failure_mode,
        }
        action_mode = execution_permission
        data_required = infer_required_data(self.analysis_claim, priced_assumptions)
        failure_cost_summary = infer_failure_cost_summary(
            priced_assumptions,
            aggregate_assumption_risk,
            penalty_if_wrong,
        )

        action_recommendation = infer_action_recommendation(
            execution_permission=execution_permission,
            expected_value=expected_value,
            expected_benefit=expected_benefit,
            risk_profile=risk_profile,
        )
        recommended_allocation = compute_recommended_allocation(
            expected_value=expected_value,
            benefit_confidence=benefit_confidence,
            toxicity_risk=self.toxicity_risk,
            reasoning_contamination_risk=self.reasoning_contamination_risk,
            execution_permission=execution_permission,
        )
        if action_mode in {"hard_stop", "consult_human"}:
            recommended_allocation = 0.0
        elif action_mode == "fetch_data_then_execute":
            recommended_allocation = min(recommended_allocation, 0.10)
        elif action_mode in {"execute_with_assumptions", "execute_small"}:
            recommended_allocation = min(recommended_allocation, 0.25)

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
            "risk_profile": risk_profile,
            "action_type": self.action_type,
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
            "cost_estimate": cost_estimate.to_dict(),
            "assumptions": assumptions,
            "assumption_pricing": priced_assumptions,
            "aggregate_assumption_risk": aggregate_assumption_risk,
            "penalty_if_wrong": penalty_if_wrong,
            "data_required": data_required,
            "failure_cost_summary": failure_cost_summary,
            "action_mode": action_mode,
            "toxicity_risk": self.toxicity_risk,
            "reasoning_contamination_risk": self.reasoning_contamination_risk,
            "expected_benefit": round(expected_benefit, 6),
            "benefit_confidence": round(benefit_confidence, 6),
            "expected_value": round(expected_value, 6),
            "opportunity_cost_of_inaction": round(opportunity_cost_of_inaction, 6),
            "action_recommendation": action_recommendation,
            "recommended_allocation": recommended_allocation,
            "bypass_simulation": bypass_simulation,
            "reason": reason,
            "next_step": self.next_step or PLACEHOLDER_TEXT,
            "claim_graph": claim_graph_payload,
            "claim_graph_warning": (claim_graph_warnings[0] if claim_graph_warnings else None),
            "claim_graph_warnings": claim_graph_warnings or None,
        }

    def print_report(self) -> None:
        """Print the claim triage report."""
        payload = self.to_dict()

        print_divider()
        print_section("ORIGINAL CLAIM", text=self.original_claim)
        print_section("ANALYSIS CLAIM", text=self.analysis_claim)
        print_section("LANGUAGE DETECTED", text=self.language_detected)
        print_section("TRANSLATION USED", text=format_bool(self.translation_used))
        print_section("RISK PROFILE", text=payload["risk_profile"])
        print_section("ACTION TYPE", text=payload["action_type"])
        print_section("CLAIM TYPE", text=self.claim_type)
        print_section("STRUCTURAL VALIDITY", text=payload["structural_validity"])
        print_section("TRUTH STATUS", text=payload["truth_status"])
        print_section("EVIDENCE STRENGTH", text=self.evidence_strength)
        print_section("BULLSHIT RISK", text=payload["bullshit_risk"])
        print_section("TOXICITY RISK", text=payload["toxicity_risk"])
        print_section("REASONING CONTAMINATION RISK", text=payload["reasoning_contamination_risk"])
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
        print_section("EXPECTED BENEFIT", text=str(payload["expected_benefit"]))
        print_section("BENEFIT CONFIDENCE", text=str(payload["benefit_confidence"]))
        print_section("EXPECTED VALUE", text=str(payload["expected_value"]))
        print_section("OPPORTUNITY COST OF INACTION", text=str(payload["opportunity_cost_of_inaction"]))
        print_section("ACTION RECOMMENDATION", text=payload["action_recommendation"])
        print_section("ACTION MODE", text=payload["action_mode"])
        print_section(
            "ASSUMPTIONS",
            items=[
                f"{item['assumption']} (failure_cost={item['failure_cost']}, testability={item['testability']}, confidence={item['confidence']})"
                for item in payload["assumption_pricing"]
            ],
        )
        print_section("DATA REQUIRED", items=payload["data_required"])
        print_section("FAILURE COST", items=payload["failure_cost_summary"])
        print_section("AGGREGATE ASSUMPTION RISK", text=payload["aggregate_assumption_risk"])
        print_section(
            "PENALTY IF WRONG",
            items=[f"{k}: {v}" for k, v in payload["penalty_if_wrong"].items()],
        )
        print_section("RECOMMENDED ALLOCATION", text=str(payload["recommended_allocation"]))
        print_section(
            "COST ESTIMATE",
            items=[
                f"base_tokens: {payload['cost_estimate']['base_tokens']}",
                f"compute_multiplier: {payload['cost_estimate']['compute_multiplier']}",
                f"correction_probability: {payload['cost_estimate']['correction_probability']}",
                f"expected_tokens: {payload['cost_estimate']['expected_tokens']}",
                f"expected_cost_usd: {payload['cost_estimate']['expected_cost_usd']}",
                f"correction_cost_usd: {payload['cost_estimate']['correction_cost_usd']}",
                f"total_expected_cost_usd: {payload['cost_estimate']['total_expected_cost_usd']}",
                f"risk_label: {payload['cost_estimate']['risk_label']}",
                f"proceed_recommendation: {payload['cost_estimate']['proceed_recommendation']}",
            ],
        )
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

        if self.interpretation:
            print_section("INTERPRETATION", text=self.interpretation)

        if self.bottom_line:
            print_section("BOTTOM LINE", text=self.bottom_line)

        if self.next_step:
            print_section("NEXT STEP", text=self.next_step)

        print_divider()


@dataclass
class ActionCostEstimate:
    """Economic estimate for claim execution under a risk profile."""

    base_tokens: int
    compute_multiplier: float
    correction_probability: float
    expected_tokens: int
    expected_cost_usd: float
    correction_cost_usd: float
    total_expected_cost_usd: float
    risk_label: str
    proceed_recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert estimate to JSON-ready dictionary."""
        payload = {
            "base_tokens": self.base_tokens,
            "compute_multiplier": round(self.compute_multiplier, 3),
            "correction_probability": round(self.correction_probability, 3),
            "expected_tokens": self.expected_tokens,
            "expected_compute_cost_usd": round(self.expected_cost_usd, 6),
            "correction_cost_usd": round(self.correction_cost_usd, 6),
            "expected_total_cost_usd": round(self.total_expected_cost_usd, 6),
            "risk_label": self.risk_label,
            "proceed_recommendation": self.proceed_recommendation,
        }
        payload["expected_cost_usd"] = payload["expected_compute_cost_usd"]
        payload["total_expected_cost_usd"] = payload["expected_total_cost_usd"]
        return payload


def infer_action_recommendation(
    *,
    execution_permission: str,
    expected_value: float,
    expected_benefit: float,
    risk_profile: str,
) -> str:
    """Recommend whether to proceed/prioritize using both risk and upside."""
    if execution_permission in {"hard_stop", "consult_human"}:
        if risk_profile == "speculative" and expected_value > 0:
            return "allow_with_warning_high_upside"
        return "do_not_act"
    if expected_value <= 0 and expected_benefit < 1.0:
        return "do_not_prioritize"
    if expected_value > 0:
        return "prioritize"
    return "monitor_only"


def compute_recommended_allocation(
    *,
    expected_value: float,
    benefit_confidence: float,
    toxicity_risk: str,
    reasoning_contamination_risk: str,
    execution_permission: str,
) -> float:
    """Compute a deterministic position/action size recommendation in [0.0, 1.0]."""
    if execution_permission in {"hard_stop", "consult_human"}:
        return 0.0

    toxicity_penalty = {"low": 0.0, "medium": 0.03, "high": 0.08, "critical": 0.2}.get(toxicity_risk, 0.03)
    contamination_penalty = {"low": 0.0, "medium": 0.03, "high": 0.08, "critical": 0.2}.get(
        reasoning_contamination_risk,
        0.03,
    )
    allocation_score = (expected_value * max(0.0, min(1.0, benefit_confidence))) - toxicity_penalty - contamination_penalty

    if allocation_score <= 0:
        return 0.0
    if allocation_score < 0.05:
        return 0.1
    if allocation_score < 0.15:
        return 0.25
    if allocation_score < 0.30:
        return 0.5
    return 1.0


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


def normalize_risk_profile(value: Any) -> str:
    """Normalize risk profile into supported values."""
    token = normalize_label(value)
    alias_map = {
        "conservative": "strict",
        "default": "balanced",
        "aggressive": "speculative",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_RISK_PROFILES else "balanced"


def normalize_action_type(value: Any) -> str:
    """Normalize action type into supported values."""
    token = normalize_label(value)
    alias_map = {
        "safe": "reversible",
        "expensive": "costly",
        "customer": "external_facing",
        "destructive": "irreversible",
    }
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_ACTION_TYPES else "reversible"


def normalize_toxicity_risk(value: Any) -> str:
    """Normalize toxicity/contamination risk level."""
    token = normalize_label(value)
    alias_map = {"very_high": "critical", "severe": "critical"}
    normalized = alias_map.get(token, token)
    return normalized if normalized in ALLOWED_TOXICITY_RISK else "medium"


def infer_action_family(text: str) -> str:
    """Map claim/assumption wording into a normalized action family."""
    lowered = text.lower()
    patterns: list[tuple[str, tuple[str, ...]]] = [
        ("dominance", ("become primary", "become the primary", "primary", "dominant", "dominate", "lead", "leader", "outpace")),
        ("replacement", ("replace", "replaces", "displace", "displaces", "substitute", "supplant")),
        ("growth", ("grow", "grows", "increase", "increases", "expand", "expands", "accelerate", "rises", "rise")),
        ("optimization", ("optimize", "optimizes", "improve", "improves", "reduce", "reduces", "efficient", "faster", "better")),
        ("persistence", ("remain", "remains", "persist", "persists", "continue", "continues", "sustain", "sustains", "stay", "stays")),
        ("causation", ("because", "therefore", "drives", "causes", "leads to", "results in")),
        ("dependency", ("depends on", "requires", "need", "needs", "relies on")),
        ("comparison", ("more than", "less than", "better than", "worse than", "than")),
    ]
    for family, tokens in patterns:
        if any(token in lowered for token in tokens):
            return family
    return "dependency"


def normalize_claimed_outcome(subject: str, action_family: str, obj: str) -> str:
    """Convert raw claim fragments into a clean outcome phrase."""
    raw = clean_text(obj, fallback="the claimed outcome")
    cleaned = raw.strip(" .")
    lowered = cleaned.lower()

    cleaned = re.sub(
        r"^(to\s+)?(become|becomes|becoming|dominate|dominates|dominating|lead|leads|leading|outpace|outpaces|outpacing)\s+",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()
    cleaned = re.sub(r"^the\s+", "", cleaned, flags=re.IGNORECASE).strip()

    if action_family == "dominance":
        if "primary" in lowered:
            base = re.sub(r"^primary\s+", "", cleaned, flags=re.IGNORECASE).strip()
            return f"primary {base} status".strip() if base else "primary status"
        return f"a dominant position in {cleaned}" if cleaned else "a dominant position"
    if action_family == "growth":
        return f"material growth in {cleaned}" if cleaned else "material growth"
    if action_family == "optimization":
        return f"measurable improvement in {cleaned}" if cleaned else "measurable improvement"
    if action_family == "replacement":
        return f"replacement of alternatives in {cleaned}" if cleaned else "replacement of alternatives"
    return cleaned or "the claimed outcome"


def extract_assumptions(claim: str) -> list[str]:
    """Extract underlying assumptions from a claim using lightweight heuristics."""
    text = clean_text(claim)
    lowered = text.lower()
    action_type = infer_action_family(lowered)

    subject = ""
    obj = ""
    structure_match = re.match(
        r"^\s*(?P<subject>[^,.;:]+?)\s+"
        r"(?P<verb>will|would|can|could|should|may|might|is|are|was|were|becomes?|become|remains?|remain|grows?|grow|replaces?|replace|depends?|depend|outpaces?|outpace|improves?|improve|optimizes?|optimize)\s+"
        r"(?P<object>.+?)\s*$",
        text,
        flags=re.IGNORECASE,
    )
    if structure_match:
        subject = clean_text(structure_match.group("subject"), fallback="")
        obj = clean_text(structure_match.group("object"), fallback="")
    else:
        atomic = [part for part in extract_atomic_claims(text) if len(part.strip()) >= 8]
        if atomic:
            parts = re.split(r"\b(will|would|can|could|should|may|might|is|are|was|were)\b", atomic[0], maxsplit=1, flags=re.IGNORECASE)
            if len(parts) >= 3:
                subject = clean_text(parts[0], fallback="")
                obj = clean_text(parts[2], fallback="")
            else:
                subject = clean_text(atomic[0], fallback="")

    if not subject and not obj:
        return [clean_text(claim)]

    entity = subject or text
    claimed_outcome = normalize_claimed_outcome(entity, action_type, obj or "the claimed outcome")

    assumptions: list[str] = []
    assumptions.append(f"Relevant actors adopt {entity} at sufficient scale")
    assumptions.append(f"Alternatives do not outperform {entity} on the relevant dimension")

    if action_type in {"dominance", "replacement", "comparison"}:
        assumptions.append(f"Observable metrics would show {entity} reaching {claimed_outcome}")
    if action_type in {"growth", "optimization", "persistence"}:
        assumptions.append(f"The advantages supporting {entity} persist over time")
    if action_type in {"causation", "dependency", "replacement", "optimization"}:
        assumptions.append(f"The key prerequisites linking {entity} to {claimed_outcome} remain valid")
    assumptions.append(f"No binding constraint prevents {entity} from achieving {claimed_outcome}")

    deduped: list[str] = []
    seen: set[str] = set()
    for assumption in assumptions:
        cleaned = clean_text(assumption)
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cleaned)

    if len(deduped) >= 2:
        return deduped[:5]
    return deduped or [clean_text(claim)]


def price_assumption_failure(
    assumption: str,
    *,
    action_type: str,
    toxicity_risk: str,
    reasoning_contamination_risk: str,
    evidence_strength: str,
) -> dict[str, Any]:
    """Price the downside of assumption failure using deterministic heuristics."""
    severity = 0
    if action_type in {"external_facing", "irreversible"}:
        severity += 2
    elif action_type == "costly":
        severity += 1

    if toxicity_risk in {"high", "critical"}:
        severity += 1
    if reasoning_contamination_risk in {"high", "critical"}:
        severity += 1
    if evidence_strength in {"weak", "none"}:
        severity += 1

    action_family = infer_action_family(assumption)
    implies_dominance = action_family == "dominance"

    failure_cost = "critical" if severity >= 4 else "high" if severity >= 3 else "medium" if severity >= 2 else "low"
    testability = "high" if evidence_strength == "strong" else "medium" if evidence_strength == "moderate" else "low"
    ranking = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    level = ranking.get(failure_cost, 0)
    if evidence_strength == "none" and testability == "low":
        level = max(level, ranking["medium"])
    if implies_dominance and evidence_strength in {"none", "weak"}:
        level = max(level, ranking["high"])
    reverse = {v: k for k, v in ranking.items()}
    failure_cost = reverse[level]
    confidence = 0.8 if evidence_strength == "strong" else 0.6 if evidence_strength == "moderate" else 0.4
    return {
        "assumption": assumption,
        "confidence": confidence,
        "failure_cost": failure_cost,
        "testability": testability,
        "action_family": action_family,
    }


def infer_aggregate_assumption_risk(priced_assumptions: list[dict[str, Any]], evidence_strength: str = "moderate") -> str:
    """Aggregate assumption-level failure costs into one risk label."""
    ranking = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_rank = max((ranking.get(item.get("failure_cost", "low"), 0) for item in priced_assumptions), default=0)
    low_testability_count = sum(1 for item in priced_assumptions if item.get("testability") == "low")
    dominance_count = sum(1 for item in priced_assumptions if item.get("action_family") == "dominance")
    if priced_assumptions and evidence_strength == "none" and low_testability_count >= max(1, len(priced_assumptions) // 2 + 1):
        max_rank = max(max_rank, ranking["medium"])
    if dominance_count > 0 and evidence_strength == "none":
        max_rank = max(max_rank, ranking["high"])
    reverse = {v: k for k, v in ranking.items()}
    return reverse[max_rank]


def infer_required_data(claim: str, assumptions: list[dict[str, Any]]) -> list[str]:
    """Infer concrete data that would most reduce assumption uncertainty."""
    data_needed: list[str] = []
    action_families = {str(item.get("action_family", "")) for item in assumptions}
    low_testability = [item for item in assumptions if item.get("testability") == "low"]

    if low_testability:
        data_needed.append("Observable metric that would confirm the claimed outcome")
    if "dominance" in action_families or "comparison" in action_families or "replacement" in action_families:
        data_needed.append("Comparison baseline against leading alternatives")
    if "dependency" in action_families or "causation" in action_families:
        data_needed.append("Constraint or dependency check that could invalidate the claim")
    if "growth" in action_families or "optimization" in action_families or "persistence" in action_families:
        data_needed.append("Time-series checkpoint showing whether the claimed trend persists")
    if not data_needed:
        data_needed.append("Pre-registered acceptance criteria for a small-scope validation run")
        data_needed.append("Observable metric that would confirm or falsify the claimed outcome")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in data_needed:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:4] if len(deduped) >= 2 else deduped + ["Comparison baseline against alternatives"][: max(0, 2 - len(deduped))]


def infer_failure_cost_summary(
    assumptions: list[dict[str, Any]],
    aggregate_assumption_risk: str,
    penalty_if_wrong: dict[str, Any],
) -> list[str]:
    """Summarize likely downside if assumptions fail."""
    summary = [
        f"Aggregate assumption risk: {aggregate_assumption_risk}",
        f"Expected loss level if wrong: {penalty_if_wrong.get('expected_loss', 'unknown')}",
        f"Likely failure mode: {penalty_if_wrong.get('likely_failure_mode', 'unknown')}",
        f"Estimated compute multiplier under failure: {penalty_if_wrong.get('cost_multiplier', 'unknown')}x",
    ]
    high_cost = [item for item in assumptions if item.get("failure_cost") in {"high", "critical"}]
    if high_cost:
        summary.append(f"High-cost assumptions identified: {len(high_cost)}")
    return summary


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


def structural_short_circuit(claim: str) -> dict[str, Any] | None:
    """Short-circuit impossible structural claims before deeper inference."""
    structural_validity = infer_structural_validity(claim)
    if structural_validity != "invalid":
        return None

    return {
        "claim_type": infer_claim_type(claim),
        "truth_status": "structurally_invalid",
        "evidence_strength": "none",
        "bullshit_risk": "very_high",
        "toxicity_risk": "critical",
        "reasoning_contamination_risk": "critical",
        "action_status": "do_not_act",
        "rewrite_required": True,
    }


def infer_toxicity_risk(claim: str, gaps: list[str], action_type: str) -> str:
    """Estimate risk that acting on this input causes harmful downstream effects."""
    text = claim.lower()
    score = 0
    if any(token in text for token in ("delete", "erase", "drop", "guarantee", "always", "all")):
        score += 2
    if len(gaps) >= 2:
        score += 1
    if action_type in {"costly", "irreversible", "external_facing"}:
        score += 1
    if score >= 4:
        return "critical"
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


def infer_reasoning_contamination_risk(claim: str, gaps: list[str], toxicity_risk: str) -> str:
    """Estimate likelihood of bad assumptions propagating into tool calls/loops."""
    text = claim.lower()
    score = 0
    if any(token in text for token in ("obvious", "guaranteed", "must", "definitely", "never")):
        score += 2
    if infer_rewrite_required(claim):
        score += 1
    if len(gaps) > 0:
        score += 1
    if toxicity_risk in {"high", "critical"}:
        score += 1
    if score >= 4:
        return "critical"
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


def compute_expected_value(*, expected_benefit: float, benefit_confidence: float, total_expected_cost_usd: float) -> float:
    """Compute expected value from upside and expected cost."""
    return (expected_benefit * benefit_confidence) - total_expected_cost_usd


def compute_action_cost_estimate(
    *,
    base_tokens: int,
    compute_multiplier: float,
    confidence: float,
    bullshit_risk: str,
    structural_validity: str,
    model_price_per_token: float,
) -> ActionCostEstimate:
    """Estimate expected action cost and correction burden."""
    confidence_penalty = max(0.1, 1.0 - confidence)
    risk_factor = {"low": 0.15, "medium": 0.35, "high": 0.65, "very_high": 0.8}.get(bullshit_risk, 0.35)
    correction_probability = min(0.95, max(0.05, (risk_factor + confidence_penalty) / 1.5))
    if structural_validity == "invalid":
        correction_probability = max(correction_probability, 0.9)

    expected_tokens = int(round(base_tokens * max(1.0, compute_multiplier)))
    expected_cost_usd = expected_tokens * model_price_per_token
    correction_cost_usd = expected_cost_usd * correction_probability * 1.5
    total_expected_cost_usd = expected_cost_usd + correction_cost_usd
    proceed_recommendation = "proceed_with_gate" if structural_validity == "valid" else "consult_human"
    risk_label = "high" if correction_probability >= 0.6 else "medium" if correction_probability >= 0.3 else "low"

    return ActionCostEstimate(
        base_tokens=base_tokens,
        compute_multiplier=compute_multiplier,
        correction_probability=correction_probability,
        expected_tokens=expected_tokens,
        expected_cost_usd=expected_cost_usd,
        correction_cost_usd=correction_cost_usd,
        total_expected_cost_usd=total_expected_cost_usd,
        risk_label=risk_label,
        proceed_recommendation=proceed_recommendation,
    )


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
    risk_profile: str,
    structural_validity: str,
) -> str:
    """Infer expected error cost as low/medium/high."""
    if structural_validity == "invalid":
        return "high"

    if truth_status == "unsupported" and structural_validity == "valid":
        if risk_profile == "speculative":
            return "medium"
        return "medium"

    if (
        bullshit_risk in {"high", "very_high"}
        or truth_status in {"unknown", "structurally_invalid"}
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
        risk_profile=normalize_risk_profile(report.risk_profile),
        structural_validity=infer_structural_validity(report.analysis_claim),
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


def infer_execution_permission(
    report: ClaimReport,
    decision_risk: str,
    risk_profile: str,
    structural_validity: str,
) -> str:
    """Infer execution mode for pre-action gate."""
    if structural_validity == "invalid":
        return "consult_human"

    if report.action_type == "irreversible" and report.truth_status in {"unknown", "unsupported"}:
        return "consult_human"

    if report.truth_status == "unsupported":
        return "fetch_data_then_execute"

    if decision_risk == "high" and (report.toxicity_risk in {"high", "critical"} or report.reasoning_contamination_risk in {"high", "critical"}):
        return "consult_human"

    if report.action_status == "safe_to_act":
        return "execute_now"

    if report.action_status == "use_with_caution" or decision_risk == "medium":
        return "execute_with_assumptions"

    return "execute_small"


def infer_enforcement_reason(
    report: ClaimReport,
    decision_risk: str,
    expected_error_cost: str,
    confidence: float,
    execution_permission: str,
    risk_profile: str,
    structural_validity: str,
    assumptions: list[str],
    aggregate_assumption_risk: str,
) -> str:
    """Infer concise reason for selected action mode."""
    if structural_validity == "invalid":
        return "consult_human: structural invalidity, impossible claim risk, and lack of independent validation"

    if execution_permission == "consult_human":
        return f"consult_human: high consequence/ambiguity with assumptions={len(assumptions)} risk={aggregate_assumption_risk}"
    if execution_permission == "fetch_data_then_execute":
        return f"fetch_data_then_execute: missing support, assumptions={len(assumptions)}"
    if execution_permission == "execute_with_assumptions":
        return f"execute_with_assumptions: priced assumptions={len(assumptions)} risk={aggregate_assumption_risk}"
    if execution_permission == "execute_small":
        return "execute_small: non-positive or uncertain value, constrained action size"
    if execution_permission == "execute_now":
        return "execute_now: sufficiently grounded with acceptable risk"
    if execution_permission == "hard_stop":
        return "hard_stop: malformed or impossible machine-invalid input"

    return "action mode selected by default policy"


def simulate_bypass(
    report: ClaimReport,
    execution_permission: str | None = None,
    structural_validity: str | None = None,
    bullshit_risk: str | None = None,
    risk_profile: str = "balanced",
) -> dict[str, Any]:
    """Simulate likely consequence of bypassing the pre-action gate."""
    decision_risk = infer_decision_risk(
        truth_status=report.truth_status,
        evidence_strength=report.evidence_strength,
        bullshit_risk=report.bullshit_risk,
    )
    validity = structural_validity or infer_structural_validity(report.analysis_claim)
    permission = execution_permission or infer_execution_permission(report, decision_risk, risk_profile, validity)
    risk = bullshit_risk or report.bullshit_risk

    if permission in {"hard_stop", "consult_human"}:
        multiplier = 5.0
        if validity == "invalid":
            multiplier = 6.0
        if validity == "invalid" and risk == "very_high":
            multiplier = 8.0
        return {
            "would_proceed": permission != "consult_human",
            "expected_outcome": "high likelihood of incorrect action",
            "estimated_loss": "high",
            "compute_multiplier": multiplier,
        }

    if permission in {"execute_with_assumptions", "fetch_data_then_execute", "execute_small"}:
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
    return [item.text for item in decompose_claim(claim)]


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


def evaluate_input(
    input_text: str,
    *,
    risk_profile: str = "balanced",
    action_type: str = "reversible",
    expected_benefit: float = 0.0,
    benefit_confidence: float = 0.0,
    opportunity_cost_of_inaction: float = 0.0,
    base_tokens: int = 4000,
    model_price: float = 0.000003,
) -> dict[str, Any]:
    """Primary interface for the Constraint Engine.

    Evaluates whether an input should be acted on under uncertainty,
    and determines expected value, risk, and recommended allocation.

    Designed for both:
    - agents (structured decision output)
    - humans (interpretable decision layer)
    """
    language_data = normalize_claim_language(input_text)
    analysis_claim = language_data["analysis_claim"]
    claim_type = infer_claim_type(analysis_claim)
    claim_graph = build_claim_graph(
        analysis_claim,
        claim_type=claim_type,
        infer_action_family_fn=infer_action_family,
        price_assumption_failure_fn=price_assumption_failure,
        extract_assumptions_fn=extract_assumptions,
        action_type=action_type,
        evidence_strength="none",
    )
    report = ClaimReport.from_dict(
        {
            "claim": input_text,
            "claim_type": claim_type,
            "risk_profile": risk_profile,
            "action_type": action_type,
            "expected_benefit": expected_benefit,
            "benefit_confidence": benefit_confidence,
            "opportunity_cost_of_inaction": opportunity_cost_of_inaction,
            "base_tokens": base_tokens,
            "model_price": model_price,
            "claim_graph": claim_graph,
        }
    )
    return report.to_dict()


@dataclass(frozen=True)
class VerificationResult:
    """Adapter-friendly verification result for middleware control layers."""

    allowed: bool
    failed_constraints: list[str]
    warnings: list[str]
    report: dict[str, Any]
    hard_constraints: list[str] = field(default_factory=list)
    logic_constraints: list[str] = field(default_factory=list)
    format_constraints: list[str] = field(default_factory=list)
    guardrail_feedback: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    decision: str = "ALLOW"
    action_mode: str = "execute_now"
    recommended_allocation: float = 0.0
    penalty_if_wrong: dict[str, Any] = field(default_factory=dict)
    aggregate_assumption_risk: str = "low"
    data_required: list[str] = field(default_factory=list)
    failure_cost_summary: list[str] = field(default_factory=list)
    cost_estimate: dict[str, Any] = field(default_factory=dict)
    retry_tax_usd: float = 0.0
    quarantine_reason: str | None = None
    audit_event: dict[str, Any] = field(default_factory=dict)


def map_execution_permission_to_decision(
    *,
    execution_permission: str,
    warnings: list[str],
    failed_constraints: list[str],
    aggregate_assumption_risk: str,
    penalty_if_wrong: dict[str, Any],
) -> tuple[str, str | None]:
    if "SENSITIVE_PROMPT_DISCLOSURE" in failed_constraints:
        return "QUARANTINE", "Sensitive prompt disclosure attempt detected"
    if execution_permission == "hard_stop":
        return "HARD_STOP", "Hard-stop execution permission from verifier"
    if execution_permission == "consult_human":
        expected_loss = str(penalty_if_wrong.get("expected_loss", "medium"))
        if aggregate_assumption_risk in {"high", "critical"} or expected_loss == "high":
            return "QUARANTINE", "High aggregate assumption risk or expected loss requires quarantine"
        return "CONSULT_HUMAN", "Human escalation required by policy"
    if execution_permission == "fetch_data_then_execute":
        return "FETCH_DATA_THEN_EXECUTE", None
    if execution_permission == "execute_small":
        return "EXECUTE_SMALL", None
    if execution_permission == "execute_with_assumptions":
        return "EXECUTE_WITH_ASSUMPTIONS", None
    if warnings:
        return "ALLOW_WITH_WARNING", None
    return "ALLOW", None


def compute_retry_tax(
    *,
    penalty_if_wrong: dict[str, Any],
    aggregate_assumption_risk: str,
    token_waste_risk: str,
    violation_count: int,
    strict_mode: bool,
) -> float:
    base = 1.0
    loss_weight = {"low": 0.1, "medium": 0.25, "high": 0.5}.get(str(penalty_if_wrong.get("expected_loss", "medium")), 0.25)
    assumption_weight = {"low": 0.0, "medium": 0.2, "high": 0.5, "critical": 0.8}.get(aggregate_assumption_risk, 0.2)
    waste_weight = {"low": 0.0, "medium": 0.1, "high": 0.35, "very_high": 0.6}.get(token_waste_risk, 0.1)
    repetition_weight = min(2.5, 0.35 * max(0, violation_count))
    strict_multiplier = 1.35 if strict_mode else 1.0
    multiplier = min(6.0, (base + loss_weight + assumption_weight + waste_weight + repetition_weight) * strict_multiplier)
    return round(multiplier, 3)


def verify_output(proposed_output: Any, context: dict[str, Any] | None = None) -> VerificationResult:
    """Evaluate proposed output and map report fields into middleware-ready control signals."""
    payload_context = context or {}
    report = evaluate_input(
        str(proposed_output),
        risk_profile=str(payload_context.get("risk_profile", "balanced")),
        action_type=str(payload_context.get("action_type", "reversible")),
        expected_benefit=float(payload_context.get("expected_benefit", 0.0)),
        benefit_confidence=float(payload_context.get("benefit_confidence", 0.0)),
        opportunity_cost_of_inaction=float(payload_context.get("opportunity_cost_of_inaction", 0.0)),
        base_tokens=int(payload_context.get("base_tokens", 4000)),
        model_price=float(payload_context.get("model_price", 0.000003)),
    )

    failed_constraints: list[str] = []
    hard_constraints: list[str] = []
    logic_constraints: list[str] = []
    format_constraints: list[str] = []
    warnings: list[str] = []
    guardrail_feedback: dict[str, list[dict[str, str]]] = {"hard": [], "logic": [], "format": []}

    def add_violation(category: str, code: str, explanation: str) -> None:
        failed_constraints.append(code)
        guardrail_feedback[category].append(
            {
                "code": code,
                "explanation": explanation,
            }
        )
        if category == "hard":
            hard_constraints.append(code)
        elif category == "logic":
            logic_constraints.append(code)
        elif category == "format":
            format_constraints.append(code)

    lower_text = str(proposed_output).lower()
    if "system prompt" in lower_text or "hidden instructions" in lower_text:
        add_violation(
            "hard",
            "SENSITIVE_PROMPT_DISCLOSURE",
            "Hard constraint violated: output appears to disclose protected system instructions.",
        )

    if report.get("structural_validity") == "invalid":
        add_violation(
            "format",
            "STRUCTURAL_VALIDITY_INVALID",
            "Format constraint violated: output is structurally invalid or unparseable.",
        )
    if report.get("execution_permission") in {"consult_human", "hard_stop"}:
        add_violation(
            "hard",
            "EXECUTION_PERMISSION_BLOCKED",
            "Hard constraint violated: policy denies direct execution for this output.",
        )
    if report.get("action_status") == "do_not_act":
        add_violation(
            "hard",
            "ACTION_STATUS_BLOCKED",
            "Hard constraint violated: action status indicates output must not be acted upon.",
        )
    if report.get("truth_status") in {"unsupported", "unknown"} and report.get("execution_permission") in {
        "execute_now",
        "execute_with_assumptions",
        "execute_small",
    }:
        add_violation(
            "logic",
            "LOGIC_INSUFFICIENT_SUPPORT",
            "Logic constraint violated: claim support is insufficient or unknown and needs rethinking.",
        )
    if bool(report.get("rewrite_required")):
        add_violation(
            "format",
            "FORMAT_REWRITE_REQUIRED",
            "Format constraint violated: output requires rewriting for structural clarity.",
        )

    for warning in (report.get("claim_graph_warnings") or []):
        warnings.append(str(warning))
    if report.get("truth_status") in {"unsupported", "unknown"}:
        warnings.append("TRUTH_STATUS_UNCERTAIN")

    report["guardrail_violations"] = guardrail_feedback
    report["guardrail_summary"] = {
        "hard_count": len(hard_constraints),
        "logic_count": len(logic_constraints),
        "format_count": len(format_constraints),
    }
    decision, quarantine_reason = map_execution_permission_to_decision(
        execution_permission=str(report.get("execution_permission", "fetch_data_then_execute")),
        warnings=warnings,
        failed_constraints=failed_constraints,
        aggregate_assumption_risk=str(report.get("aggregate_assumption_risk", "low")),
        penalty_if_wrong=dict(report.get("penalty_if_wrong") or {}),
    )
    retry_tax_usd = compute_retry_tax(
        penalty_if_wrong=dict(report.get("penalty_if_wrong") or {}),
        aggregate_assumption_risk=str(report.get("aggregate_assumption_risk", "low")),
        token_waste_risk=str(report.get("token_waste_risk", "medium")),
        violation_count=int(payload_context.get("violation_count", 0)),
        strict_mode=bool(payload_context.get("strict_mode", False)),
    )
    expected_total_cost_usd = float((report.get("cost_estimate") or {}).get("expected_total_cost_usd", (report.get("cost_estimate") or {}).get("total_expected_cost_usd", 0.0)))
    audit_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "proposed_output_hash": hashlib.sha256(str(proposed_output).encode("utf-8")).hexdigest(),
        "decision": decision,
        "failed_constraints": failed_constraints,
        "warnings": warnings,
        "aggregate_assumption_risk": report.get("aggregate_assumption_risk"),
        "token_waste_risk": report.get("token_waste_risk"),
        "retry_tax_usd": retry_tax_usd,
        "estimated_total_cost_usd": expected_total_cost_usd,
        "output_released": False,
        "session_reset": False,
    }
    report["decision"] = decision
    report["retry_tax_usd"] = retry_tax_usd
    report["quarantine_reason"] = quarantine_reason
    expected_value = float(report.get("expected_value", 0.0))
    aggregate_assumption_risk = str(report.get("aggregate_assumption_risk", "low"))
    if decision == "QUARANTINE":
        routing_recommendation = "quarantine_and_review"
    elif decision == "FETCH_DATA_THEN_EXECUTE":
        routing_recommendation = "fetch_data_then_verify"
    elif decision in {"EXECUTE_SMALL", "EXECUTE_WITH_ASSUMPTIONS"}:
        routing_recommendation = "execute_small_then_verify"
    elif expected_value >= 0 and retry_tax_usd <= 1.5 and aggregate_assumption_risk in {"low", "medium"}:
        routing_recommendation = "verify_then_execute"
    else:
        routing_recommendation = "fetch_data_then_verify"
    report["cost_aware_routing_recommendation"] = routing_recommendation

    return VerificationResult(
        allowed=decision in {"ALLOW", "ALLOW_WITH_WARNING", "EXECUTE_SMALL", "EXECUTE_WITH_ASSUMPTIONS"},
        failed_constraints=failed_constraints,
        warnings=warnings,
        report=report,
        hard_constraints=hard_constraints,
        logic_constraints=logic_constraints,
        format_constraints=format_constraints,
        guardrail_feedback=guardrail_feedback,
        decision=decision,
        action_mode=str(report.get("action_mode", "fetch_data_then_execute")),
        recommended_allocation=float(report.get("recommended_allocation", 0.0)),
        penalty_if_wrong=dict(report.get("penalty_if_wrong") or {}),
        aggregate_assumption_risk=str(report.get("aggregate_assumption_risk", "low")),
        data_required=[str(item) for item in (report.get("data_required") or [])],
        failure_cost_summary=[str(item) for item in (report.get("failure_cost_summary") or [])],
        cost_estimate=dict(report.get("cost_estimate") or {}),
        retry_tax_usd=retry_tax_usd,
        quarantine_reason=quarantine_reason,
        audit_event=audit_event,
    )


def evaluate_inputs(
    inputs: list[str],
    *,
    risk_profile: str = "balanced",
    action_type: str = "reversible",
    expected_benefit: float = 0.0,
    benefit_confidence: float = 0.0,
    opportunity_cost_of_inaction: float = 0.0,
    base_tokens: int = 4000,
    model_price: float = 0.000003,
) -> list[dict[str, Any]]:
    """Batch interface for evaluating multiple inputs with shared parameters."""
    return [
        evaluate_input(
            item,
            risk_profile=risk_profile,
            action_type=action_type,
            expected_benefit=expected_benefit,
            benefit_confidence=benefit_confidence,
            opportunity_cost_of_inaction=opportunity_cost_of_inaction,
            base_tokens=base_tokens,
            model_price=model_price,
        )
        for item in inputs
    ]


def evaluate_text(
    text: str,
    *,
    risk_profile: str = "balanced",
    action_type: str = "reversible",
    expected_benefit: float = 0.0,
    benefit_confidence: float = 0.0,
    opportunity_cost_of_inaction: float = 0.0,
    base_tokens: int = 4000,
    model_price: float = 0.000003,
) -> list[dict[str, Any]]:
    """Evaluate raw text by extracting candidate claims and returning JSON-ready reports."""
    raw_claims = extract_claims_from_text(text)
    return evaluate_inputs(
        raw_claims,
        risk_profile=risk_profile,
        action_type=action_type,
        expected_benefit=expected_benefit,
        benefit_confidence=benefit_confidence,
        opportunity_cost_of_inaction=opportunity_cost_of_inaction,
        base_tokens=base_tokens,
        model_price=model_price,
    )


def evaluate_claim(
    claim: str,
    *,
    risk_profile: str = "balanced",
    action_type: str = "reversible",
    expected_benefit: float = 0.0,
    benefit_confidence: float = 0.0,
    opportunity_cost_of_inaction: float = 0.0,
    base_tokens: int = 4000,
    model_price: float = 0.000003,
) -> dict[str, Any]:
    """Evaluate one claim string and return a JSON-ready report dictionary."""
    return evaluate_input(
        claim,
        risk_profile=risk_profile,
        action_type=action_type,
        expected_benefit=expected_benefit,
        benefit_confidence=benefit_confidence,
        opportunity_cost_of_inaction=opportunity_cost_of_inaction,
        base_tokens=base_tokens,
        model_price=model_price,
    )


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
            "claim": "A new tokenization approach could significantly reduce inference cost in volatile market-monitoring agents.",
            "action_type": "costly",
            "risk_profile": "speculative",
            "sources": ["Internal pilot notes"],
            "facts": ["Pilot showed reduced token usage on one benchmark."],
            "gaps": ["No production validation yet."],
            "truth_status": "unknown",
            "expected_benefit": 3.0,
            "benefit_confidence": 0.45,
            "opportunity_cost_of_inaction": 1.2,
            "next_step": "Run controlled canary before scaling.",
        },
        {
            "claim": "Send apology email to the affected enterprise customer and include a temporary remediation timeline.",
            "action_type": "external_facing",
            "risk_profile": "balanced",
            "sources": ["Support incident summary"],
            "facts": ["Outage lasted 42 minutes and customer escalation is open."],
            "gaps": ["Legal wording not yet approved."],
            "truth_status": "mixed",
            "expected_benefit": 1.4,
            "benefit_confidence": 0.65,
            "opportunity_cost_of_inaction": 0.9,
            "next_step": "Require legal/comms signoff before send.",
        },
        {
            "claim": "Delete the legacy finance exports directory immediately to prevent duplicate reconciliation runs.",
            "action_type": "irreversible",
            "risk_profile": "strict",
            "sources": ["Operator request in chat"],
            "facts": [],
            "gaps": ["No backup confirmation provided."],
            "truth_status": "unknown",
            "expected_benefit": 0.7,
            "benefit_confidence": 0.3,
            "opportunity_cost_of_inaction": 0.2,
            "next_step": "Consult_human and require backup + approval ticket.",
        },
        {
            "claim": "Call several APIs and optimize latency quickly; pick whichever endpoint seems fastest.",
            "action_type": "reversible",
            "risk_profile": "balanced",
            "sources": [],
            "facts": [],
            "gaps": ["No endpoint list, SLA target, or rollback criteria."],
            "truth_status": "unknown",
            "expected_benefit": 0.9,
            "benefit_confidence": 0.35,
            "opportunity_cost_of_inaction": 0.4,
            "next_step": "Decompose into explicit API calls, metrics, and stop conditions.",
        },
        {
            "claim": "A single AI firewall update will eliminate all cybersecurity breaches forever across every system.",
            "action_type": "external_facing",
            "risk_profile": "speculative",
            "sources": ["Vendor claim deck"],
            "facts": ["No universal guarantee has been demonstrated."],
            "gaps": ["Absolute impossible guarantee and no independent validation."],
            "truth_status": "unknown",
            "expected_benefit": 2.5,
            "benefit_confidence": 0.25,
            "opportunity_cost_of_inaction": 1.0,
            "next_step": "Consult human due to structural invalidity and lack of reliable validation.",
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
    parser.add_argument(
        "--base-tokens",
        type=int,
        default=4000,
        help="Base token budget used for cost estimation (default: 4000).",
    )
    parser.add_argument(
        "--model-price",
        type=float,
        default=0.000003,
        help="USD price per token for cost estimation (default: 0.000003).",
    )
    parser.add_argument(
        "--risk-profile",
        type=str,
        default="balanced",
        choices=sorted(ALLOWED_RISK_PROFILES),
        help="Risk profile for execution gating and cost posture.",
    )
    parser.add_argument(
        "--action-type",
        type=str,
        default="reversible",
        choices=sorted(ALLOWED_ACTION_TYPES),
        help="Action type describing reversibility and externality of execution.",
    )
    parser.add_argument(
        "--expected-benefit",
        type=float,
        default=0.0,
        help="Expected benefit input used for expected value calculation.",
    )
    parser.add_argument(
        "--benefit-confidence",
        type=float,
        default=0.0,
        help="Confidence in expected benefit in range [0,1].",
    )
    parser.add_argument(
        "--opportunity-cost-of-inaction",
        type=float,
        default=0.0,
        help="Opportunity cost if no action is taken.",
    )
    return parser.parse_args()


def main() -> int:
    """Entry point for the CLI."""
    args = parse_args()

    default_options = {
        "risk_profile": normalize_risk_profile(args.risk_profile),
        "action_type": normalize_action_type(args.action_type),
        "expected_benefit": args.expected_benefit,
        "benefit_confidence": args.benefit_confidence,
        "opportunity_cost_of_inaction": args.opportunity_cost_of_inaction,
        "base_tokens": args.base_tokens,
        "model_price": args.model_price,
    }
    risk_profile_overridden = "--risk-profile" in sys.argv
    base_tokens_overridden = "--base-tokens" in sys.argv
    model_price_overridden = "--model-price" in sys.argv
    action_type_overridden = "--action-type" in sys.argv
    expected_benefit_overridden = "--expected-benefit" in sys.argv
    benefit_confidence_overridden = "--benefit-confidence" in sys.argv
    opportunity_cost_of_inaction_overridden = "--opportunity-cost-of-inaction" in sys.argv

    if args.text_input is not None:
        raw_claims = extract_claims_from_text(args.text_input)
        claims = [ClaimReport.from_dict({"claim": claim, **default_options}) for claim in raw_claims]
    elif args.input is not None:
        claims = load_claims_from_json(args.input)
        for claim in claims:
            if risk_profile_overridden:
                claim.risk_profile = default_options["risk_profile"]
            if base_tokens_overridden:
                claim.base_tokens = default_options["base_tokens"]
            if model_price_overridden:
                claim.model_price = default_options["model_price"]
            if action_type_overridden:
                claim.action_type = default_options["action_type"]
            if expected_benefit_overridden:
                claim.expected_benefit = default_options["expected_benefit"]
            if benefit_confidence_overridden:
                claim.benefit_confidence = default_options["benefit_confidence"]
            if opportunity_cost_of_inaction_overridden:
                claim.opportunity_cost_of_inaction = default_options["opportunity_cost_of_inaction"]
    else:
        claims = get_sample_claims()
        for claim in claims:
            if risk_profile_overridden:
                claim.risk_profile = default_options["risk_profile"]
            if base_tokens_overridden:
                claim.base_tokens = default_options["base_tokens"]
            if model_price_overridden:
                claim.model_price = default_options["model_price"]
            if action_type_overridden:
                claim.action_type = default_options["action_type"]
            if expected_benefit_overridden:
                claim.expected_benefit = default_options["expected_benefit"]
            if benefit_confidence_overridden:
                claim.benefit_confidence = default_options["benefit_confidence"]
            if opportunity_cost_of_inaction_overridden:
                claim.opportunity_cost_of_inaction = default_options["opportunity_cost_of_inaction"]

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
