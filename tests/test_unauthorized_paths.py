import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from authority import InMemoryUsedTokenStore, SQLiteUsedTokenStore, build_token, compute_payload_hash, serialize_token
from gate import KeyRing, _GlassWingCore, configure_authority, execute, issue_governance_token, mint_issuance_ticket, register_tool
from mcp_executor import PaymentGate, SQLitePaymentGate, SecurityViolationError


class UnauthorizedPathAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "audit-secret"
        self.key_id = "kid-v1"
        self.agent_id = "agent-a"
        self.intent = "safe_scan"
        self.tool_name = "tool.scan"
        self.policy_ids = ["policy.constitution.v1"]

    def _ctx(self, token: str | None) -> dict:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return {
            "agent_id": self.agent_id,
            "tenant_id": "tenant-1",
            "session_id": "sess-1",
            "tool_id": self.tool_name,
            "model_id": "model-z",
            "runtime_id": "runtime-z",
            "delegated_scope": "tool:scan",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-1",
            "jti": "jti-1",
            "policy_ids": self.policy_ids,
            "governance_token": token,
        }

    def _issue_token(self, tool_name: str, payload: dict, ctx: dict | None = None) -> str:
        context = dict(ctx or self._ctx(None))
        context["governance_issuance_ticket"] = mint_issuance_ticket(self.intent, context, tool_name, payload)
        return issue_governance_token(self.intent, context, tool_name, payload)

    def test_direct_core_access_fails(self):
        with self.assertRaises(RuntimeError):
            _GlassWingCore().run("unsafe")

    def test_executor_cannot_bootstrap_lifecycle(self):
        store = InMemoryUsedTokenStore()
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=store,
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        raw_token = serialize_token(
            build_token(
                key_id=self.key_id,
                agent_id=self.agent_id,
                intent=self.intent,
                tool_name=self.tool_name,
                policy_ids=self.policy_ids,
                payload_hash=compute_payload_hash(payload),
                secret=self.secret,
            )
        )
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(raw_token), self.tool_name, payload)
        from authority import deserialize_token

        self.assertIsNone(store.get_status(deserialize_token(raw_token).token_id))

    def test_missing_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(None), self.tool_name, {"claim": "safe"})

    def test_forged_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        token = self._issue_token(self.tool_name, payload)
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(forged), self.tool_name, payload)

    def test_replay_fails_after_restart_with_sqlite_store(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "tokens.db")

        payload = {"claim": "safe"}
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=SQLiteUsedTokenStore(db),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        token = self._issue_token(self.tool_name, payload)
        execute(self.intent, self._ctx(token), self.tool_name, payload)

        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=SQLiteUsedTokenStore(db),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(token), self.tool_name, payload)
        tmp.cleanup()

    def test_wrong_tool_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        token = self._issue_token("tool.other", payload)
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(token), self.tool_name, payload)

    def test_wrong_agent_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0, "agent-b": 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        token = self._issue_token(self.tool_name, payload, {**self._ctx(None), "agent_id": "agent-b"})
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(token), self.tool_name, payload)

    def test_payment_gate_transactional_locking_under_concurrency(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "payments.db")
        gate = SQLitePaymentGate(db)
        gate.seed_balance("a", 10.0)

        results: list[bool] = []

        def worker() -> None:
            results.append(gate.lock_bond("a", 7.0))

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(sum(1 for r in results if r), 1)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
