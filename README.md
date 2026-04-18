# Constraint-Engine

Constraint-Engine is a pre-action decision engine for humans and AI agents.

It does not determine truth.  
It determines whether action is justified under uncertainty — and how much to commit.

---

## Core Idea

Every action is a bet.

Constraint-Engine evaluates that bet before execution using three forces:

- **Expected Value (EV)** → potential upside  
- **Confidence** → reliability of that upside  
- **Risk / Toxicity** → cost of being wrong  

The output is not binary.

It answers:

- should action occur  
- how much to allocate  
- what the expected cost of error is  

---

## What It Does

For any input claim or task, the engine computes:

- structural validity  
- truth status (heuristic)  
- evidence strength  
- toxicity risk  
- reasoning contamination risk  
- expected cost (tokens / USD)  
- expected benefit  
- expected value (EV)

And produces:

```json
{
  "execution_permission": "allow_with_warning",
  "expected_value": 0.12,
  "risk_label": "high",
  "recommended_allocation": 0.25
}

---

## Why agents use this first

The cognitive firewall improves economics, not just safety:

- It **reduces wasted retries** by forcing uncertain outputs into fetch-data or bounded paths before expensive execution.
- It **prevents high-cost bad releases** through quarantine/hard-stop decisions when expected failure cost is high.
- It **routes uncertainty into cheaper workflows** (`fetch_data_then_verify`, `execute_small_then_verify`) instead of full-risk execution.
- It **improves expected economics** by making retry costs explicit (`retry_tax_usd`) and surfacing developer-facing value metrics (`expected_compute_saved_usd`, `expected_failure_cost_avoided_usd`, `firewall_value_score`).
