import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from audit import ALLOWED_CODES
from audit import AuditLogger
from gate import submit_action
from identity import build_identity_envelope
from kms_provider import DevHMACProvider
from receipt import issue_receipt, validate_receipt
from reputation import ReputationRecord, reputation_tier, update_reputation
from toxic_cost import price_toxic_tokens


class ZeroTrustGateTests(unittest.TestCase):
    def test_audit_code_registry_is_valid(self):
        required = {
            'ALLOW',
            'DENY',
            'FALLBACK_USED',
            'INVALID_SIGNATURE',
            'EXPIRED_RECEIPT',
            'PAYLOAD_MISMATCH',
            'POLICY_REAUTH',
            'REPEATED_DENIALS',
            'DEGRADED_REASONING',
            'ACTION_MISMATCH',
            'INVALID_KEY',
            'INVALID_DECISION',
            'RECEIPT_NOT_YET_VALID',
            'INVALID_TIME_WINDOW',
        }
        self.assertIsInstance(ALLOWED_CODES, set)
        self.assertEqual(ALLOWED_CODES, required)

    def _context(self) -> dict:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return {
            'agent_id': 'agent-a',
            'tenant_id': 'tenant-1',
            'session_id': 'sess-1',
            'tool_id': 'tool-x',
            'model_id': 'model-y',
            'runtime_id': 'rt-z',
            'delegated_scope': 'write:task',
            'issued_at': now.isoformat(),
            'expires_at': (now + timedelta(minutes=5)).isoformat(),
            'nonce': 'n1',
            'jti': 'j1',
            'retry_count': 0,
        }

    def test_identity_envelope_is_deterministic(self):
        ctx = self._context()
        env1 = build_identity_envelope(action_name='act', payload={'claim': 'x'}, context=ctx, policy_version='dev', key_id='k1')
        env2 = build_identity_envelope(action_name='act', payload={'claim': 'x'}, context=ctx, policy_version='dev', key_id='k1')
        self.assertEqual(env1.to_dict(), env2.to_dict())

    def test_receipt_binds_exact_payload_and_action(self):
        provider = DevHMACProvider()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        ok, _ = validate_receipt(receipt, action_name='scan', payload={'claim': 'a'}, provider=provider)
        bad, code = validate_receipt(receipt, action_name='scan', payload={'claim': 'b'}, provider=provider)
        self.assertTrue(ok)
        self.assertFalse(bad)
        self.assertEqual(code, 'PAYLOAD_MISMATCH')

    def test_action_mismatch_blocks_execution(self):
        provider = DevHMACProvider()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        ok, code = validate_receipt(receipt, action_name='other_action', payload={'claim': 'a'}, provider=provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'ACTION_MISMATCH')

    def test_invalid_signature_blocks_execution(self):
        provider = DevHMACProvider()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        tampered = receipt.__class__(**{**receipt.to_dict(), 'signature': 'bad'})
        ok, code = validate_receipt(tampered, action_name='scan', payload={'claim': 'a'}, provider=provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'INVALID_SIGNATURE')

    def test_expired_receipt_blocks_execution(self):
        provider = DevHMACProvider()
        ctx = self._context()
        now = datetime.now(timezone.utc)
        ctx['issued_at'] = (now - timedelta(minutes=10)).isoformat()
        ctx['expires_at'] = (now - timedelta(minutes=1)).isoformat()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=ctx, policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        ok, code = validate_receipt(receipt, action_name='scan', payload={'claim': 'a'}, provider=provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'EXPIRED_RECEIPT')

    def test_payload_mismatch_blocks_execution(self):
        provider = DevHMACProvider()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        ok, code = validate_receipt(receipt, action_name='scan', payload={'claim': 'zzz'}, provider=provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'PAYLOAD_MISMATCH')

    def test_invalid_key_blocks_execution(self):
        provider = DevHMACProvider(kid='key-a')
        other_provider = DevHMACProvider(kid='key-b')
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='ALLOW', provider=provider)
        ok, code = validate_receipt(receipt, action_name='scan', payload={'claim': 'a'}, provider=other_provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'INVALID_KEY')

    def test_invalid_identity_requires_reauth(self):
        provider = DevHMACProvider()
        called = {'n': 0}
        ctx = self._context()
        ctx['expires_at'] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
        ctx['issued_at'] = datetime.now(timezone.utc).isoformat()

        def executor(_r, _p):
            called['n'] += 1
            return {'ok': True}

        out = submit_action('safe_scan', {'claim': 'stable claim'}, ctx, executor, provider=provider)
        self.assertFalse(out['executed'])
        self.assertEqual(out['decision'], 'REQUIRE_REAUTH')
        self.assertEqual(called['n'], 0)

    def test_gate_builds_identity_envelope_once(self):
        provider = DevHMACProvider()
        called = {'n': 0}

        def executor(_r, _p):
            called['n'] += 1
            return {'ok': True}

        with patch('gate.build_identity_envelope', wraps=build_identity_envelope) as wrapped:
            submit_action('safe_scan', {'claim': 'System has measurable 99% uptime in 30 days'}, self._context(), executor, provider=provider)
            self.assertEqual(wrapped.call_count, 1)

    def test_require_reauth_receipt_cannot_execute(self):
        provider = DevHMACProvider()
        env = build_identity_envelope(action_name='scan', payload={'claim': 'a'}, context=self._context(), policy_version='dev', key_id=provider.key_id())
        receipt = issue_receipt(env, decision='REQUIRE_REAUTH', provider=provider)
        ok, code = validate_receipt(receipt, action_name='scan', payload={'claim': 'a'}, provider=provider)
        self.assertFalse(ok)
        self.assertEqual(code, 'INVALID_DECISION')

    def test_denied_actions_never_call_executor(self):
        provider = DevHMACProvider()
        called = {'n': 0}

        def executor(_r, _p):
            called['n'] += 1
            return {'ok': True}

        out = submit_action('dangerous_delete', {'claim': 'Delete all systems forever'}, self._context(), executor, provider=provider)
        self.assertFalse(out['executed'])
        self.assertEqual(called['n'], 0)

    def test_allowed_actions_call_executor_once(self):
        provider = DevHMACProvider()
        called = {'n': 0}

        def executor(_r, _p):
            called['n'] += 1
            return {'ok': True}

        out = submit_action('safe_scan', {'claim': 'System has measurable 99% uptime in 30 days'}, self._context(), executor, provider=provider)
        self.assertTrue(out['executed'])
        self.assertEqual(called['n'], 1)

    def test_fallback_and_degraded_reasoning_produce_audit_events(self):
        provider = DevHMACProvider()
        tmp = tempfile.TemporaryDirectory()
        logger = AuditLogger(Path(tmp.name) / 'audit.jsonl')

        def executor(_r, _p):
            return {'ok': True}

        submit_action('safe_scan', {'claim': 'OpenAI API will reduce token cost next quarter'}, self._context(), executor, provider=provider, audit_logger=logger)
        data = (Path(tmp.name) / 'audit.jsonl').read_text(encoding='utf-8')
        self.assertIn('ALLOW', data)

    def test_reputation_score_changes_deterministically_with_failures(self):
        rec = ReputationRecord()
        for _ in range(4):
            update_reputation(rec, warning_codes=['x'], fallback_used=True, denied=True, retried=True, invalid_signature=False, confidence=0.2, degraded=True)
        self.assertEqual(reputation_tier(rec), 'QUARANTINED')

    def test_toxic_token_multiplier_increases_with_worse_patterns(self):
        low = price_toxic_tokens(warning_codes=[], fallback_used=False, denial_history=0, confidence=0.9, evidence_strength='strong', claim_graph_invalidity=False, retry_count=0, reputation_tier='TRUSTED')
        high = price_toxic_tokens(warning_codes=['a', 'b'], fallback_used=True, denial_history=5, confidence=0.1, evidence_strength='none', claim_graph_invalidity=True, retry_count=5, reputation_tier='HIGH_RISK')
        self.assertGreater(high['toxic_token_multiplier'], low['toxic_token_multiplier'])


if __name__ == '__main__':
    unittest.main()
