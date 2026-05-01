import unittest

from simulation_governance import ScenarioAssumption, run_scenario_simulation


class SimulationGovernanceTests(unittest.TestCase):
    def test_low_survival_rate_blocks(self):
        out = run_scenario_simulation(
            "x",
            [ScenarioAssumption("a", 0.0, 0.1, 0.2, 1.0, True)],
            simulation_count=400,
            seed=7,
        )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertEqual(out["max_allocation_pct"], 0.0)

    def test_medium_survival_rate_speculate(self):
        out = run_scenario_simulation(
            "x",
            [ScenarioAssumption("a", 0.2, 0.65, 0.9, 1.0, True)],
            simulation_count=400,
            seed=4,
        )
        self.assertEqual(out["decision"], "SPECULATE")
        self.assertIn(out["max_allocation_pct"], [0.5, 1.0, 2.0])

    def test_high_survival_rate_speculate_max_cap(self):
        out = run_scenario_simulation(
            "x",
            [ScenarioAssumption("a", 0.8, 0.9, 1.0, 1.0, True)],
            simulation_count=400,
            seed=9,
        )
        self.assertEqual(out["decision"], "SPECULATE")
        self.assertEqual(out["max_allocation_pct"], 2.0)

    def test_simulation_never_returns_allow(self):
        out = run_scenario_simulation(
            "x",
            [ScenarioAssumption("a", 0.9, 1.0, 1.0, 1.0, True)],
            simulation_count=200,
            seed=1,
        )
        self.assertNotEqual(out["decision"], "ALLOW")

    def test_fragile_critical_assumption_marked(self):
        out = run_scenario_simulation(
            "x",
            [
                ScenarioAssumption("critical_driver", 0.0, 0.9, 1.0, 1.5, True),
                ScenarioAssumption("secondary", 0.4, 0.7, 0.9, 0.5, False),
            ],
            simulation_count=500,
            seed=3,
        )
        self.assertIn("critical_driver", out["fragile_assumptions"])


if __name__ == "__main__":
    unittest.main()
