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
