import unittest

from claim_graph import build_claim_graph, decompose_claim, extract_entities
from verify import evaluate_input


class ClaimGraphTests(unittest.TestCase):
    def test_simple_claim(self) -> None:
        text = "Coinbase supports USDC settlements"
        graph = build_claim_graph(text, claim_type="factual")
        self.assertGreaterEqual(len(graph.atomic_claims), 1)
        self.assertGreaterEqual(len(graph.assumptions), 1)
        self.assertGreaterEqual(len(graph.required_evidence), 1)

    def test_compound_claim(self) -> None:
        text = "Coinbase will dominate agent payments and USDC will become primary settlement because fees are lower"
        atomic = decompose_claim(text)
        self.assertGreaterEqual(len(atomic), 2)
        graph = build_claim_graph(text, claim_type="forward_looking")
        self.assertGreaterEqual(len(graph.atomic_claims), 2)
        self.assertTrue(any(item.type in {"comparison", "validation", "constraint_check"} for item in graph.required_evidence))

    def test_forward_looking_claim(self) -> None:
        text = "OpenAI API will reduce token cost next quarter"
        graph = build_claim_graph(text, claim_type="forward_looking")
        self.assertEqual(graph.time_scope, "forward_looking")
        self.assertTrue(any(item.type == "validation" for item in graph.required_evidence))

    def test_vague_claim(self) -> None:
        text = "This system is better"
        graph = build_claim_graph(text, claim_type="opinion")
        self.assertGreaterEqual(len(graph.required_evidence), 1)
        entities = extract_entities(text)
        self.assertGreaterEqual(len(entities), 1)

    def test_evaluate_input_includes_claim_graph(self) -> None:
        payload = evaluate_input("Coinbase will dominate agent payments", expected_benefit=100, benefit_confidence=0.4)
        self.assertIn("claim_graph", payload)
        self.assertIsInstance(payload["claim_graph"], dict)
        self.assertGreaterEqual(len(payload["claim_graph"]["assumptions"]), 1)


if __name__ == "__main__":
    unittest.main()
