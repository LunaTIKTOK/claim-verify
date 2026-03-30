Constraint Engine (formerly claim-verify)

A pre-action decision engine for humans and agents.

---

What this is

Constraint Engine evaluates whether an action is worth executing by pricing:

- uncertainty
- reasoning quality
- expected cost
- expected benefit

before the action is taken.

It does not try to determine truth in isolation.

It determines whether an input is safe enough, coherent enough, and valuable enough to act on.

---

Core idea

Every action is a bet.

The question is not:

«Is this claim true?»

The question is:

«What happens if I act on this?»

Constraint Engine answers that by estimating:

- structural validity
- toxicity risk
- reasoning contamination risk
- expected compute cost
- correction cost
- expected error cost
- expected benefit
- expected value

---

What is a toxic token?

A toxic token is any input that is likely to:

- waste compute
- generate bad downstream reasoning
- trigger unnecessary tool calls
- create correction loops
- cause costly or irreversible mistakes

The engine detects and prices these before execution.

---

Output

For any input (claim, instruction, or plan), the engine returns:

- structural_validity
- toxicity_risk
- reasoning_contamination_risk
- evidence_strength
- decision_risk

Cost surface:

- expected_compute_cost
- correction_cost
- total_expected_cost

Value surface:

- expected_benefit
- opportunity_cost_of_inaction
- expected_value

Execution:

- execution_permission
- proceed_recommendation
- enforcement_reason

---

Risk Profiles

The engine supports three execution modes:

strict

Optimized for safety.

- blocks structurally invalid inputs
- blocks high-risk uncertainty for costly or irreversible actions
- minimizes downside

---

balanced

Default mode.

- allows uncertainty with warnings
- blocks only extreme risk
- balances progress and safety

---

speculative

Optimized for asymmetric upside.

- allows structurally valid but unproven inputs
- relies on cost and expected value rather than certainty
- enables exploration and alpha

---

Action Types

Execution decisions depend on the type of action:

- reversible
- costly
- external_facing
- irreversible

The same input may be allowed or blocked depending on the action.

---

What this is NOT

- not a fact-checker
- not a chatbot
- not a research report generator
- not a trading signal engine

This is a decision layer.

---

Example

Input:
"Coinbase will dominate agent payments"

Output:

- structurally valid
- high uncertainty
- moderate toxicity risk

Cost:

- expected cost of being wrong

Value:

- potential upside if correct

Result:

- allow_with_warning (speculative profile)
- rewrite_required for precision

---

Why this exists

In agent systems, the failure mode is not being wrong.

The failure mode is:

«compounding error from acting on weak inputs»

Constraint Engine is the inhibition layer that prevents that.

---

Use cases

- AI agents deciding whether to execute tasks
- evaluating instructions before running code or API calls
- filtering low-quality reasoning in autonomous workflows
- trading, research, and decision systems
- any environment where acting on bad inputs is costly

---

Philosophy

Do not optimize for certainty.

Optimize for:

«expected value under uncertainty»

---

Status

Early-stage system.

The core engine is stable.

The cost and value layers are evolving.

---

Name

Originally built as "claim-verify".

Now evolving into a broader system:

«Constraint Engine — a general-purpose decision layer for humans and agents»
