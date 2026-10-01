"""Tests for the real-data pipeline: loaders, bridge, N5 real-data encoding.
Loader tests use tiny fixture files in the exact dataset formats, so they
run without the (large) datasets."""

import csv
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zkmob.bridge import Unsupported, from_circuit_policy, to_circuit_policy  # noqa: E402
from zkmob.datasets import (BEIJING, PORTO, SegmentRules, Trip, iter_porto, read_plt, read_tdrive,  # noqa: E402
                            segment, time_split)
from zkmob.leakage import (World, answers, exact_partition, leakage_from_partition, leakage_from_remaining,  # noqa: E402
                           make_candidates, make_pool, simulate, simulate_budget, to_points, transcript_bound_bits)
from zkmob.n5_real import PAD, Window, dedupe, to_cells  # noqa: E402
from zkmob.policy import Avoid, Box, Dwell, Ordered, Policy, Step, Visit, evaluate  # noqa: E402
from zkmob.trajectory import Point  # noqa: E402

PLT = """Geolife trajectory
WGS 84
Altitude is in Feet
Reserved 3
0,2,255,My Track,0,0,2,8421376
0
39.984702,116.318417,0,492,39744.1201851852,2008-10-23,02:53:04
39.984683,116.318450,0,492,39744.1202546296,2008-10-23,02:53:10
39.984686,116.318417,0,492,39744.1203125,2008-10-23,02:53:15
"""


class Loaders(unittest.TestCase):
    def test_read_plt_and_tdrive(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.plt"
            p.write_text(PLT)
            fixes = read_plt(p)
            self.assertEqual(len(fixes), 3)
            self.assertAlmostEqual(fixes[0][0], 39.984702)          # lat first
            self.assertEqual(fixes[1][2] - fixes[0][2], 6)
            q = Path(d) / "1.txt"
            q.write_text("1,2008-02-02 15:46:08,116.51135,39.93883\n1,2008-02-02 15:36:08,116.51172,39.92123\n")
            fx = read_tdrive(q)
            self.assertEqual(fx[0][0], 39.92123)                     # lon/lat swapped, sorted by time
            self.assertEqual(fx[1][2] - fx[0][2], 600)

    def test_iter_porto(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "train.csv"
            with open(p, "w", newline="") as fh:
                w = csv.writer(fh, quoting=csv.QUOTE_ALL)
                w.writerow(["TRIP_ID", "CALL_TYPE", "ORIGIN_CALL", "ORIGIN_STAND", "TAXI_ID", "TIMESTAMP",
                            "DAY_TYPE", "MISSING_DATA", "POLYLINE"])
                w.writerow(["1", "C", "", "", "7", "1000", "A", "False", "[[-8.61,41.14],[-8.62,41.15]]"])
                w.writerow(["2", "C", "", "", "7", "2000", "A", "True", "[[-8.61,41.14]]"])
            rows = list(iter_porto(p))
            self.assertEqual(len(rows), 1)                           # missing-data row dropped
            tid, taxi, t0, fixes = rows[0]
            self.assertEqual(fixes[1], (41.15, -8.62, 1015))         # 15 s sampling, lat first

    def test_segment_rules(self):
        lat0, lon0 = BEIJING.lat0, BEIJING.lon0
        fixes = [(lat0 + 1e-5 * i, lon0, 1000 + 10 * i) for i in range(100)]        # 1 m / 10 s
        fixes += [(lat0, lon0, 1000 + 10 * 99)]                                       # duplicate time
        fixes += [(lat0 + 0.5, lon0, 1000 + 10 * 100)]                                # 55 km jump
        fixes += [(lat0 + 1e-5 * i, lon0, 5000 + 10 * i) for i in range(100)]        # after a gap
        segs = segment(sorted(fixes, key=lambda f: f[2]), BEIJING, SegmentRules(gap_s=600, min_dur_s=60))
        self.assertEqual([len(s) for s in segs], [100, 100])
        rules = SegmentRules(gap_s=600, min_dur_s=60, max_dur_s=300)
        self.assertTrue(all(s[-1][2] - s[0][2] <= 300 for s in segment(fixes[:100], BEIJING, rules)))

    def test_projection_origin_and_split(self):
        x, y = PORTO.project(PORTO.lat0, PORTO.lon0)
        self.assertEqual((x, y), (PORTO.half_m, PORTO.half_m))
        trips = [Trip("d", "u", str(i), start, [Point(0, 0, 0)]) for i, start in enumerate([5, 1, 4, 2, 3])]
        hist, ev = time_split(trips, 0.6)
        self.assertEqual([t.start for t in hist], [1, 2, 3])
        self.assertEqual([t.start for t in ev], [4, 5])


class Bridge(unittest.TestCase):
    A, B, Z = Box(0, 10, 0, 10), Box(20, 30, 20, 30), Box(50, 60, 50, 60)

    def test_roundtrip(self):
        pol = Policy([Ordered([Step(self.A), Step(self.B, 90)]), Avoid(self.Z)])
        spec = json.loads(json.dumps(to_circuit_policy(pol)))
        back = from_circuit_policy(spec)
        rng = random.Random(0)
        for _ in range(100):
            tr = [Point(rng.randrange(70), rng.randrange(70), 10 * i) for i in range(15)]
            self.assertEqual(evaluate(pol, tr), evaluate(back, tr))
        self.assertEqual(to_circuit_policy(Policy([Visit(self.A)]))["steps"][0]["max_gap"], None)

    def test_unsupported(self):
        for bad in (Policy([Dwell(self.A, 60)]),
                    Policy([Ordered([Step(self.A)]), Ordered([Step(self.B)])]),
                    Policy([Visit(self.A), Avoid(self.Z), Avoid(self.B)]),
                    Policy([Ordered([Step(self.A, 5)])])):
            with self.assertRaises(Unsupported):
                to_circuit_policy(bad)


class RealLeakageEncoding(unittest.TestCase):
    def test_padded_cells_match_reference(self):
        win = Window(0, 0, 10, cell_m=100)
        rng = random.Random(4)
        trips = []
        for i in range(30):
            n = rng.randrange(5, 40)
            pts, x, y, t = [], rng.randrange(1000), rng.randrange(1000), 0
            for _ in range(n):
                pts.append(Point(x, y, t))
                x = min(max(x + rng.randrange(-150, 151), 0), 999)
                y = min(max(y + rng.randrange(-150, 151), 0), 999)
                t += rng.choice([10, 20, 30])
            trips.append(Trip("t", "u", str(i), i, pts))
        cells, kept = to_cells(trips, win, period=20, length=25, min_ticks=1)
        self.assertEqual(len(kept), len(trips))
        self.assertTrue((cells[:, :, 0] == PAD).any())               # some trips are padded
        w = World(grid=10, cell_m=100, steps=25, step_s=20, n_candidates=len(cells))
        weights = np.ones((10, 10))
        weights[:3, :3] = 50
        for side in (1, 3):
            for q in make_pool(w, side, 40, seed=side, weights=weights, gap_steps=(2, 5)):
                vec = answers(cells, q)
                for m in range(len(cells)):
                    pts = [p for p in to_points(cells[m], w) if p.x >= 0]   # drop padding
                    self.assertEqual(bool(vec[m]), evaluate(q.to_policy(w), pts), (q, m))

    def test_weighted_pool_and_dedupe(self):
        w = World(grid=10)
        weights = np.zeros((10, 10))
        weights[7, 2] = 1.0
        for q in make_pool(w, 1, 50, seed=3, weights=weights):
            self.assertEqual(q.a, (7, 2))
        c = np.zeros((3, 4, 2), dtype=np.int32)
        c[2, 0] = (1, 1)
        self.assertEqual(len(dedupe(c)), 2)


class BudgetSimulation(unittest.TestCase):
    def test_budget_matches_plain_simulation_and_is_monotone(self):
        w = World(n_candidates=300)
        cands = make_candidates(w, seed=2)
        pool = make_pool(w, 2, 200, seed=3)
        budgets = (1, 2, 4, 8)
        # charge="all" + adaptive: remaining at B equals the plain simulation after B queries (trial 0)
        rb = simulate_budget(cands, pool, "adaptive", budgets, trials=1, seed=9, charge="all")
        rs = simulate(cands, pool, "adaptive", max_q=8, trials=1, seed=9)
        self.assertEqual(list(rb[0]), [int(rs[0, b]) for b in budgets])
        for charge, att in (("all", "adaptive"), ("yes_only", "adaptive"), ("yes_only", "cheap")):
            r = simulate_budget(cands, pool, att, budgets, trials=5, seed=4, charge=charge)
            self.assertTrue((r >= 1).all(), "the true candidate is never eliminated")
            self.assertTrue((np.diff(r, axis=1) <= 0).all(), "more budget never increases the anonymity set")


class SlhDsaEstimate(unittest.TestCase):
    def test_sizes_match_fips205(self):
        from zkmob.slh_dsa_estimate import FIPS205, count
        for p in FIPS205:
            self.assertEqual(p.sig_bytes(), p.fips_sig_bytes, p.name)
            self.assertEqual(p.length, 2 * p.n + 3, p.name)       # w = 16
            self.assertEqual(p.h, p.d * p.hp, p.name)
        c = count(FIPS205[0])                                       # 128s by hand
        self.assertEqual(c["f_calls"], 14 + 7 * 35 * 15)
        self.assertEqual(c["h_calls"], 14 * 12 + 7 * 9)


class LeakageBounds(unittest.TestCase):
    def setUp(self):
        w = World(n_candidates=250)
        self.cands = make_candidates(w, seed=11)
        self.pool = make_pool(w, 2, 150, seed=12)
        self.A = np.stack([answers(self.cands, q) for q in self.pool])

    def test_transcript_bound_values(self):
        self.assertEqual(transcript_bound_bits(3, 100, "all"), 3.0)
        self.assertAlmostEqual(transcript_bound_bits(1, 100, "yes_only"), np.log2(101))
        self.assertAlmostEqual(transcript_bound_bits(2, 10, "yes_only"), np.log2(1 + 10 + 45))

    def test_exact_partition_respects_bounds(self):
        M = self.A.shape[1]
        for charge in ("all", "yes_only"):
            for att in ("adaptive", "cheap"):
                for b, q in ((1, 30), (2, 30), (3, 100)):
                    leaves = exact_partition(self.A, att, b, charge, q)
                    self.assertEqual(sum(leaves), M)
                    met = leakage_from_partition(leaves)
                    bound = transcript_bound_bits(b, q, charge)
                    self.assertLessEqual(met["minent_bits"], bound + 1e-9)
                    self.assertLessEqual(met["shannon_bits"], met["minent_bits"] + 1e-9)  # Shannon <= min-capacity

    def test_exact_matches_simulation(self):
        # every simulated end state is one of the exact leaves (same deterministic strategy)
        for charge, att in (("all", "adaptive"), ("yes_only", "cheap")):
            leaves = set(exact_partition(self.A, att, 2, charge, 40))
            r = simulate_budget(self.cands, self.pool, att, (2,), trials=25, seed=5, charge=charge, max_total=40)
            self.assertTrue(set(r[:, 0].tolist()) <= leaves, (charge, att))

    def test_remaining_metrics(self):
        m = leakage_from_remaining(np.array([1, 1, 4, 4]), 16)
        self.assertAlmostEqual(m["shannon_bits"], (4 + 4 + 2 + 2) / 4)
        self.assertAlmostEqual(m["minent_bits"], np.log2(16 * (1 + 1 + 0.25 + 0.25) / 4))


if __name__ == "__main__":
    unittest.main()
