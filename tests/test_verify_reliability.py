import unittest
from unittest.mock import patch

from claim_graph import build_claim_graph
import verify
from verify import ClaimReport, evaluate_input, evaluate_text


class VerifyReliabilityTests(unittest.TestCase):
    def test_evaluate_input_builds_claim_graph_from_analysis_language(self) -> None:
        payload = evaluate_input(
            "Coinbase dominará los pagos de agentes y USDC se convertirá en la capa principal de liquidación para agentes de IA"
        )
        self.assertEqual(payload["language_detected"], "non_english")
        self.assertTrue(payload["translation_used"])
        self.assertIsInstance(payload["claim_graph"], dict)
        self.assertIn("coinbase will dominate agent payments", payload["claim_graph"]["normalized_text"])

    def test_to_dict_skips_repricing_when_claim_graph_exists(self) -> None:
        report = ClaimReport.from_dict(
            {
                "claim": "OpenAI API will reduce token cost next quarter",
                "claim_graph": build_claim_graph("OpenAI API will reduce token cost next quarter", claim_type="forward_looking"),
            }
        )
        with patch("verify.extract_assumptions", side_effect=AssertionError("unexpected extraction")), patch(
            "verify.price_assumption_failure",
            side_effect=AssertionError("unexpected pricing"),
        ):
            output = report.to_dict()
        self.assertIn("assumption_pricing", output)
        self.assertGreaterEqual(len(output["assumption_pricing"]), 1)

    def test_to_dict_reuses_initial_cost_when_permission_unchanged(self) -> None:
        report = ClaimReport.from_dict({"claim": "This system will always dominate"})
        with patch("verify.compute_action_cost_estimate", wraps=verify.compute_action_cost_estimate) as mocked:
            output = report.to_dict()
        self.assertEqual(output["execution_permission"], "consult_human")
        self.assertEqual(mocked.call_count, 1)

    def test_evaluate_text_compound_sentence_has_stable_non_empty_count(self) -> None:
        text = "Coinbase will dominate agent payments and USDC will settle faster because fees are lower."
        first = evaluate_text(text)
        second = evaluate_text(text)
        self.assertGreater(len(first), 0)
        self.assertEqual(len(first), len(second))
        self.assertTrue(all(isinstance(item, dict) for item in first))
        self.assertTrue(all(isinstance(item, dict) for item in second))

    def test_evaluate_text_punctuation_heavy_uses_batch_handoff(self) -> None:
        text = "OpenAI API improves latency; however, costs rise, and reliability improves, because retries drop."
        with patch("verify.evaluate_inputs", return_value=[{"ok": True}]) as mocked:
            result = evaluate_text(text, risk_profile="strict", action_type="costly")

        mocked.assert_called_once()
        args, kwargs = mocked.call_args
        self.assertIsInstance(args[0], list)
        self.assertGreater(len(args[0]), 0)
        self.assertTrue(all(isinstance(item, str) for item in args[0]))
        self.assertEqual(kwargs["risk_profile"], "strict")
        self.assertEqual(kwargs["action_type"], "costly")
        self.assertEqual(result, [{"ok": True}])

    def test_to_dict_accepts_claim_graph_dict_and_rejects_invalid_type(self) -> None:
        payload = evaluate_input("OpenAI API will reduce token cost next quarter")
        report_from_dict_graph = ClaimReport.from_dict(
            {
                "claim": payload["claim"],
                "claim_graph": payload["claim_graph"],
            }
        )
        output = report_from_dict_graph.to_dict()
        self.assertIn("claim_graph", output)
        self.assertIsInstance(output["claim_graph"], dict)

        invalid = ClaimReport.from_dict({"claim": "x", "claim_graph": "not_a_graph"})
        with self.assertRaises(TypeError):
            invalid.to_dict()

    def test_to_dict_claim_graph_assumption_schema_validation(self) -> None:
        report = ClaimReport.from_dict(
            {
                "claim": "OpenAI API will reduce token cost next quarter",
                "claim_graph": {
                    "atomic_claims": [{"text": "OpenAI API will reduce token cost next quarter"}],
                    "assumptions": [{"text": "Missing required keys"}],
                },
            }
        )
        with patch("verify.extract_assumptions", return_value=["fallback assumption"]), patch(
            "verify.price_assumption_failure",
            return_value={
                "assumption": "fallback assumption",
                "confidence": 0.4,
                "failure_cost": "medium",
                "testability": "low",
                "action_family": "dependency",
            },
        ):
            payload = report.to_dict()
        self.assertEqual(payload["assumptions"], ["fallback assumption"])
        self.assertEqual(payload["assumption_pricing"][0]["assumption"], "fallback assumption")
        self.assertIsNotNone(payload["claim_graph_warning"])
        self.assertIsInstance(payload["claim_graph_warnings"], list)

    def test_to_dict_claim_graph_atomic_claims_type_falls_back(self) -> None:
        report = ClaimReport.from_dict(
            {
                "claim": "OpenAI API will reduce token cost next quarter",
                "claim_graph": {
                    "atomic_claims": "not_a_list",
                    "assumptions": [
                        {
                            "text": "assumption",
                            "confidence": 0.5,
                            "failure_cost": "medium",
                            "testability": "low",
                            "action_family": "dependency",
                        }
                    ],
                },
            }
        )
        with patch("verify.extract_assumptions", return_value=["fallback assumption"]), patch(
            "verify.price_assumption_failure",
            return_value={
                "assumption": "fallback assumption",
                "confidence": 0.4,
                "failure_cost": "medium",
                "testability": "low",
                "action_family": "dependency",
            },
        ):
            payload = report.to_dict()
        self.assertEqual(payload["assumptions"], ["fallback assumption"])
        self.assertIsNotNone(payload["claim_graph_warning"])
        self.assertIsInstance(payload["claim_graph_warnings"], list)

    def test_to_dict_claim_graph_atomic_claims_item_shape_falls_back(self) -> None:
        report = ClaimReport.from_dict(
            {
                "claim": "OpenAI API will reduce token cost next quarter",
                "claim_graph": {
                    "atomic_claims": [{"id": "missing_text"}],
                    "assumptions": [
                        {
                            "text": "assumption",
                            "confidence": 0.5,
                            "failure_cost": "medium",
                            "testability": "low",
                            "action_family": "dependency",
                        }
                    ],
                },
            }
        )
        with patch("verify.extract_assumptions", return_value=["fallback assumption"]), patch(
            "verify.price_assumption_failure",
            return_value={
                "assumption": "fallback assumption",
                "confidence": 0.4,
                "failure_cost": "medium",
                "testability": "low",
                "action_family": "dependency",
            },
        ):
            payload = report.to_dict()
        self.assertEqual(payload["assumptions"], ["fallback assumption"])
        self.assertIsNotNone(payload["claim_graph_warning"])
        self.assertIsInstance(payload["claim_graph_warnings"], list)


if __name__ == "__main__":
    unittest.main()
