from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from intent_classification import IntentClass


class RuntimeState(str, Enum):
    RESEARCH = "RESEARCH"
    DRAFTING = "DRAFTING"
    READ_ONLY = "READ_ONLY"
    TRANSACTION = "TRANSACTION"
    PRIVILEGED = "PRIVILEGED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    QUARANTINED = "QUARANTINED"


ConstraintLevel = Literal["HARD", "SOFT", "GOAL"]


@dataclass
class CorrectionRequirement:
    violation_type: str
    required_action: str
    required_fields: list[str] = field(default_factory=list)
    suggested_next_state: RuntimeState = RuntimeState.HUMAN_REVIEW
    retry_allowed: bool = True
    human_review_required: bool = False


@dataclass
class GovernanceViolation:
    policy_id: str
    level: ConstraintLevel
    reason: str


@dataclass
class GovernanceDecision:
    status: Literal["ALLOW", "DENY", "ALLOW_WITH_JUSTIFICATION"]
    current_state: RuntimeState
    next_state: RuntimeState
    violated_policies: list[GovernanceViolation]
    correction_requirement: CorrectionRequirement | None
    retry_tax_usd: float
    bond_forfeited_usd: float
    human_review_required: bool


DEFAULT_TRANSITIONS: dict[RuntimeState, set[RuntimeState]] = {
    RuntimeState.RESEARCH: {RuntimeState.DRAFTING, RuntimeState.READ_ONLY, RuntimeState.HUMAN_REVIEW},
    RuntimeState.DRAFTING: {RuntimeState.READ_ONLY, RuntimeState.TRANSACTION, RuntimeState.HUMAN_REVIEW},
    RuntimeState.READ_ONLY: {RuntimeState.DRAFTING, RuntimeState.TRANSACTION, RuntimeState.HUMAN_REVIEW},
    RuntimeState.TRANSACTION: {RuntimeState.PRIVILEGED, RuntimeState.HUMAN_REVIEW, RuntimeState.READ_ONLY},
    RuntimeState.PRIVILEGED: {RuntimeState.HUMAN_REVIEW, RuntimeState.READ_ONLY},
    RuntimeState.HUMAN_REVIEW: {
        RuntimeState.RESEARCH,
        RuntimeState.DRAFTING,
        RuntimeState.READ_ONLY,
        RuntimeState.TRANSACTION,
        RuntimeState.PRIVILEGED,
    },
    RuntimeState.QUARANTINED: {RuntimeState.HUMAN_REVIEW, RuntimeState.QUARANTINED},
}


@dataclass
class Constraint:
    policy_id: str
    level: ConstraintLevel
    applies_to_states: set[RuntimeState] = field(default_factory=set)
    denied_transitions: set[tuple[RuntimeState, RuntimeState]] = field(default_factory=set)
    denied_tools: set[str] = field(default_factory=set)


@dataclass
class PackRule:
    id: str
    level: ConstraintLevel
    applies_in_states: list[str]
    allowed_next_states: list[str]
    intent_classes: list[str]
    violation_type: str
    required_action: str
    human_review_required: bool
    required_fields: list[str] = field(default_factory=list)


def _base_correction(action: str, suggested: RuntimeState, human: bool = False) -> CorrectionRequirement:
    return CorrectionRequirement(
        violation_type=action,
        required_action=action,
        required_fields=["actor_context", "justification"] if human else ["actor_context"],
        suggested_next_state=suggested,
        retry_allowed=not human,
        human_review_required=human,
    )


def _load_pack_rules(pack_paths: list[str] | None) -> list[PackRule]:
    rules: list[PackRule] = []
    for path in pack_paths or []:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for raw in data.get("rules", []):
            rules.append(
                PackRule(
                    id=str(raw["id"]),
                    level=str(raw["level"]).upper(),
                    applies_in_states=[str(x) for x in raw.get("applies_in_states", [])],
                    allowed_next_states=[str(x) for x in raw.get("allowed_next_states", [])],
                    intent_classes=[str(x) for x in raw.get("intent_classes", [])],
                    violation_type=str(raw["violation_type"]),
                    required_action=str(raw["required_action"]),
                    human_review_required=bool(raw.get("human_review_required", False)),
                    required_fields=[str(x) for x in raw.get("required_fields", [])],
                )
            )
    return rules


def _rule_applies(
    *,
    rule: PackRule,
    current_state: RuntimeState,
    requested_next_state: RuntimeState,
    intent_class: IntentClass,
) -> bool:
    if rule.applies_in_states and current_state.value not in set(rule.applies_in_states):
        return False
    if rule.intent_classes and str(intent_class) not in set(rule.intent_classes):
        return False
    if rule.allowed_next_states and requested_next_state.value in set(rule.allowed_next_states):
        return False
    return True


def evaluate_runtime_governance(
    *,
    current_state: RuntimeState,
    requested_next_state: RuntimeState,
    tool_name: str,
    intent_class: IntentClass,
    actor_identity_ok: bool,
    approval_token_present: bool,
    solvency_ok: bool,
    reputation_tier: str,
    soft_override_justification: str | None = None,
    constraints: list[Constraint] | None = None,
    context: dict[str, Any] | None = None,
    policy_pack_paths: list[str] | None = None,
) -> GovernanceDecision:
    context = context or {}
    violations: list[GovernanceViolation] = []
    correction: CorrectionRequirement | None = None

    if requested_next_state not in DEFAULT_TRANSITIONS.get(current_state, set()):
        violations.append(GovernanceViolation("STATE-TRANSITION", "HARD", "Requested state transition is not allowed"))
        correction = _base_correction("DOWNGRADE_TO_READ_ONLY", RuntimeState.READ_ONLY)

    if not actor_identity_ok:
        violations.append(GovernanceViolation("IDENTITY-001", "HARD", "Actor identity validation failed"))
        correction = _base_correction("FETCH_APPROVAL_TOKEN", RuntimeState.HUMAN_REVIEW, human=True)

    if current_state == RuntimeState.QUARANTINED and requested_next_state != RuntimeState.HUMAN_REVIEW:
        violations.append(GovernanceViolation("STATE-QUARANTINE", "HARD", "Quarantined state cannot execute"))
        correction = _base_correction("REQUIRE_HUMAN_APPROVAL", RuntimeState.HUMAN_REVIEW, human=True)

    if intent_class in {"PAYMENT", "TRADE"}:
        if not approval_token_present:
            violations.append(GovernanceViolation("FIN-001", "HARD", "Approval token required for financial action"))
            correction = _base_correction("FETCH_APPROVAL_TOKEN", RuntimeState.HUMAN_REVIEW)
        if not solvency_ok:
            violations.append(GovernanceViolation("FIN-002", "HARD", "Insufficient solvency"))
            correction = _base_correction("SPLIT_ORDER_SIZE", RuntimeState.READ_ONLY)

    if intent_class == "DATA_EXPORT" and bool(context.get("contains_pii", False)):
        violations.append(GovernanceViolation("PRIV-001", "HARD", "PII must be redacted before export"))
        correction = _base_correction("REDACT_PII", RuntimeState.READ_ONLY)

    if reputation_tier in {"HIGH_RISK", "QUARANTINED"} and requested_next_state == RuntimeState.PRIVILEGED:
        violations.append(GovernanceViolation("REP-001", "SOFT", "High-risk reputation cannot elevate without justification"))
        if not soft_override_justification:
            correction = _base_correction("REQUIRE_HUMAN_APPROVAL", RuntimeState.HUMAN_REVIEW, human=True)

    for c in constraints or []:
        if c.applies_to_states and current_state not in c.applies_to_states:
            continue
        if (current_state, requested_next_state) in c.denied_transitions:
            violations.append(GovernanceViolation(c.policy_id, c.level, "Denied by transition constraint"))
            correction = _base_correction("DOWNGRADE_TO_READ_ONLY", RuntimeState.READ_ONLY)
        if tool_name in c.denied_tools:
            violations.append(GovernanceViolation(c.policy_id, c.level, "Denied by tool constraint"))
            correction = _base_correction("RETRY_WITH_SOURCE", RuntimeState.READ_ONLY)

    for rule in _load_pack_rules(policy_pack_paths):
        if not _rule_applies(
            rule=rule,
            current_state=current_state,
            requested_next_state=requested_next_state,
            intent_class=intent_class,
        ):
            continue
        violations.append(
            GovernanceViolation(
                policy_id=rule.id,
                level=rule.level,
                reason=f"Violated policy pack rule: {rule.violation_type}",
            )
        )
        correction = CorrectionRequirement(
            violation_type=rule.violation_type,
            required_action=rule.required_action,
            required_fields=list(rule.required_fields),
            suggested_next_state=RuntimeState.HUMAN_REVIEW if rule.human_review_required else RuntimeState.READ_ONLY,
            retry_allowed=not rule.human_review_required,
            human_review_required=rule.human_review_required,
        )

    hard_violations = [v for v in violations if v.level == "HARD"]
    soft_violations = [v for v in violations if v.level == "SOFT"]

    if hard_violations:
        return GovernanceDecision(
            status="DENY",
            current_state=current_state,
            next_state=current_state if correction is None else correction.suggested_next_state,
            violated_policies=violations,
            correction_requirement=correction,
            retry_tax_usd=1.75,
            bond_forfeited_usd=5.0,
            human_review_required=bool(correction and correction.human_review_required),
        )

    if soft_violations and not soft_override_justification:
        return GovernanceDecision(
            status="DENY",
            current_state=current_state,
            next_state=current_state if correction is None else correction.suggested_next_state,
            violated_policies=violations,
            correction_requirement=correction,
            retry_tax_usd=0.65,
            bond_forfeited_usd=0.0,
            human_review_required=bool(correction and correction.human_review_required),
        )

    if soft_violations and soft_override_justification:
        return GovernanceDecision(
            status="ALLOW_WITH_JUSTIFICATION",
            current_state=current_state,
            next_state=requested_next_state,
            violated_policies=violations,
            correction_requirement=None,
            retry_tax_usd=0.25,
            bond_forfeited_usd=0.0,
            human_review_required=False,
        )

    return GovernanceDecision(
        status="ALLOW",
        current_state=current_state,
        next_state=requested_next_state,
        violated_policies=[],
        correction_requirement=None,
        retry_tax_usd=0.0,
        bond_forfeited_usd=0.0,
        human_review_required=False,
    )
