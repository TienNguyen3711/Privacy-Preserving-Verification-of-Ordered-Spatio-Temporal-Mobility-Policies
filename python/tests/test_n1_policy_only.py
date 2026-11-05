import csv
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "results"


@unittest.skipUnless((RES / "n1_clock_geolife.csv").exists(), "run the n1_clock binary first")
class PolicyOnlyExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, "-m", "zkmob.n1_policy_only"], cwd=ROOT, check=True,
                       env={"PYTHONPATH": str(ROOT / "python")}, capture_output=True)
        cls.rows = list(csv.DictReader(open(RES / "n1_policy_only.csv")))

    def test_whole_relation_ratio_matches_adopted_n1_fair(self):
        for prefix, summary in (("n1_real", "n1_fair_summary.csv"), ("n1_grid", "n1_grid_summary.csv")):
            fair = {(r["dataset"], r["bucket_s"]): float(r["ratio_e2e"]) for r in csv.DictReader(open(RES / summary))}
            mine = [r for r in self.rows if r["workload"] == prefix]
            self.assertEqual(len(mine), len(fair))
            for r in mine:
                self.assertAlmostEqual(float(r["e2e_bucket_over_scan"]), fair[(r["dataset"], r["bucket_s"])], delta=6e-4)  # n1_fair rounds to 3 places

    def test_all_policies_covered_and_clock_is_close_to_scan(self):
        widths = {r["bucket_s"] for r in self.rows}
        total = sum(int(r["items"]) for r in self.rows) // len(widths)
        self.assertEqual(total, 9298)  # 4,800 trace-anchored + 4,498 grid policies
        for r in self.rows:
            self.assertGreater(float(r["clock_over_scan"]), 1.0)
            self.assertLess(float(r["clock_over_scan"]), 1.01)
            self.assertGreater(float(r["scan_over_selector"]), 10)


if __name__ == "__main__":
    unittest.main()
