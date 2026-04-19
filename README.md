# Constraint-Engine

Constraint-Engine is a **constitutional authority layer for agent execution**.

The model/runtime is an **untrusted proposer**.
The authority layer is the **trusted executor**.

## Single Public Execution Surface

There is exactly one allowed execution path:

```python
execute(intent: str, actor_context: dict, tool_name: str, tool_args: dict)
```

Any direct core execution path or direct tool invocation path is unauthorized and must fail closed.

## Governance Authorization Is Mandatory

All downstream tools require valid governance authorization on every call.
A governance token is required and must be:

- signed (HMAC-SHA256)
- scoped to agent + intent + tool + policy set
- time-bounded (`issued_at` / `expires_at`)
- one-time use

Unauthorized execution path attempts are **security violations**.

## Solvency and Bond Enforcement

Execution also requires solvency and bond locking:

- bond lock before execution
- bond release on valid execution
- bond forfeiture on invalid/missing/replayed token attempts

## Replay Token Persistence Strategy

`authority.py` provides a replay-store interface (`UsedTokenStore`) and default
`InMemoryUsedTokenStore` implementation.

- **Current default:** in-memory store (suitable for tests/dev)
- **Production requirement:** implement `UsedTokenStore` with persistent shared storage
  (e.g., redis/database/kv) so consumed token ids survive process restarts and scale-out.

## Demo

```bash
python middleware_example.py
```

Shows:

- authorized execution
- forged token blocked
- replay blocked
- insufficient balance lockout
- direct bypass blocked
