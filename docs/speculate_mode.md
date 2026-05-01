# SPECULATE Mode

## Decision states

- `ALLOW`: high-confidence, critical assumptions are verified/observable, normal governed execution.
- `SPECULATE`: forward-looking thesis has uncertainty; execution is allowed only with bounded allocation.
- `BLOCK`: uncertainty or governance constraints fail; no execution.

## Assumption maps

SPECULATE mode uses structured assumption maps:

- claim
- assumptions (status, confidence, evidence, criticality, falsification trigger)
- confidence average
- max allocation
- falsification trigger set

This makes uncertainty checks deterministic and auditable.

## Confidence thresholds

- `< 0.45` → `BLOCK`
- `0.45 <= confidence < 0.75` → `SPECULATE`
- `>= 0.75` with critical assumptions verified/observable → `ALLOW`

Additional hard blocks:

- any critical `UNSUPPORTED` assumption
- contradictory evidence markers

## Allocation caps

For `SPECULATE` decisions:

- confidence `< 0.50` → max allocation `0.5%`
- confidence `< 0.60` → max allocation `1.0%`
- otherwise (`< 0.75`) → max allocation `2.0%`

If requested allocation is missing or above cap, request is blocked before token issuance.

## Falsification triggers

Each assumption can carry a falsification trigger. These triggers are emitted in interceptor output so operators can monitor thesis breakpoints and tighten policy or unwind exposure.

## Why speculation is allowed but bounded

Forward-looking work (investing, capacity planning, scenario strategy) often cannot be fully verified in advance. Cognitive-firewall allows this work only in bounded form: explicit assumptions, explicit confidence, hard caps, and normal token-governed execution controls.
