import unittest

from uncertainty_governance import Assumption, AssumptionMap, AssumptionStatus, evaluate_uncertainty


class UncertaintyGovernanceTests(unittest.TestCase):
    def test_unsupported_critical_assumption_blocks(self):
        out = evaluate_uncertainty(
            AssumptionMap(
                claim="x",
                assumptions=[Assumption("a", AssumptionStatus.UNSUPPORTED, 0.8, ["no data"], "trigger", True)],
                mode="INVESTING",
                confidence_average=0.8,
                max_allocation_pct=2.0,
                falsification_triggers=["trigger"],
            )
        )
        self.assertEqual(out["decision"], "BLOCK")

    def test_contradiction_blocks(self):
        out = evaluate_uncertainty(
            AssumptionMap(
                claim="x",
                assumptions=[Assumption("a", AssumptionStatus.OBSERVABLE, 0.8, ["data contradict prior thesis"], "trigger", True)],
                mode="INVESTING",
                confidence_average=0.8,
                max_allocation_pct=2.0,
                falsification_triggers=["trigger"],
            )
        )
        self.assertEqual(out["decision"], "BLOCK")

    def test_mixed_observable_speculative_returns_speculate(self):
        out = evaluate_uncertainty(
            AssumptionMap(
                claim="x",
                assumptions=[
                    Assumption("a", AssumptionStatus.OBSERVABLE, 0.7, ["signal"], "t1", True),
                    Assumption("b", AssumptionStatus.SPECULATIVE, 0.6, ["signal"], "t2", False),
                ],
                mode="INVESTING",
                confidence_average=0.65,
                max_allocation_pct=3.0,
                falsification_triggers=["t1", "t2"],
            )
        )
        self.assertEqual(out["decision"], "SPECULATE")
        self.assertEqual(out["max_allocation_pct"], 2.0)

    def test_verified_high_confidence_allows(self):
        out = evaluate_uncertainty(
            AssumptionMap(
                claim="x",
                assumptions=[Assumption("a", AssumptionStatus.VERIFIED, 0.9, ["signal"], "t1", True)],
                mode="INVESTING",
                confidence_average=0.9,
                max_allocation_pct=4.0,
                falsification_triggers=["t1"],
            )
        )
        self.assertEqual(out["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
