import json
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zkmob.leakage import World, answers, make_candidates, make_pool, to_points  # noqa: E402
from zkmob.policy import Avoid, Box, Dwell, Ordered, Policy, Step, Visit, evaluate, ordered_witness, policy_from_dict  # noqa: E402
from zkmob.trajectory import Point, synthetic_diagonal, validate  # noqa: E402


def around(f, r=150):
    cx = 1000 + int(8000 * f)
    return Box(cx - r, cx + r, cx - r, cx + r)


class PolicySemantics(unittest.TestCase):
    def setUp(self):
        self.traj = synthetic_diagonal(3600, 5)
        self.A, self.B = around(0.2), around(0.4)

    def test_matches_rust_scenario(self):
        # same scenario as the Rust pilot: A at ~720 s, B at ~1440 s
        w = ordered_witness(self.traj, [Step(self.A), Step(self.B, 900)])
        self.assertIsNotNone(w)
        self.assertLess(w[0], w[1])
        self.assertIsNone(ordered_witness(self.traj, [Step(self.A), Step(self.B, 300)]))

    def test_order_matters(self):
        self.assertFalse(evaluate(Policy([Ordered([Step(self.B), Step(self.A)])]), self.traj))
        self.assertTrue(evaluate(Policy([Ordered([Step(self.A), Step(self.B)])]), self.traj))

    def test_avoid_visit_dwell(self):
        off = Box(7000, 8000, 1000, 2000)
        on = Box(4000, 6000, 4000, 6000)
        self.assertTrue(evaluate(Policy([Avoid(off), Visit(self.A)]), self.traj))
        self.assertFalse(evaluate(Policy([Avoid(on)]), self.traj))
        self.assertTrue(evaluate(Policy([Dwell(on, 300)]), self.traj))
        self.assertFalse(evaluate(Policy([Dwell(self.A, 3000)]), self.traj))

    def test_bruteforce_agreement(self):
        rng = random.Random(3)
        for _ in range(200):
            traj = [Point(rng.randrange(10), rng.randrange(10), i * 10) for i in range(12)]
            za = Box(0, 4, 0, 4)
            zb = Box(5, 9, 5, 9)
            gap = rng.choice([20, 50, 200])
            brute = any(za.contains(traj[i]) and zb.contains(traj[j]) and traj[j].t - traj[i].t <= gap
                        for i in range(len(traj)) for j in range(i + 1, len(traj)))
            self.assertEqual(evaluate(Policy([Ordered([Step(za), Step(zb, gap)])]), traj), brute)

    def test_json_spec(self):
        spec = json.loads(json.dumps({
            "zones": {"A": vars(self.A), "B": vars(self.B), "Z": {"xmin": 7000, "xmax": 8000, "ymin": 1000, "ymax": 2000}},
            "clauses": [{"ordered": [{"zone": "A"}, {"zone": "B", "max_gap": 900}]}, {"avoid": "Z"}],
        }))
        self.assertTrue(evaluate(policy_from_dict(spec), self.traj))

    def test_validate(self):
        validate(self.traj)
        with self.assertRaises(ValueError):
            validate([Point(0, 0, 10), Point(0, 0, 5)])


class LeakageVectorised(unittest.TestCase):
    def test_vectorised_matches_reference(self):
        w = World(n_candidates=60)
        cands = make_candidates(w, seed=5)
        for side in (1, 3):
            for q in make_pool(w, side, 40, seed=6):
                vec = answers(cands, q)
                for m in range(0, 60, 7):
                    ref = evaluate(q.to_policy(w), to_points(cands[m], w))
                    self.assertEqual(bool(vec[m]), ref, (q, m))


if __name__ == "__main__":
    unittest.main()
