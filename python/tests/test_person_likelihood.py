"""Exact person-level likelihood for K distinct trips (review R6, 1 Oct 2026)."""
import itertools
import random
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zkmob.n5_bounds import distinct_assignments, falling  # noqa: E402


class PersonLikelihood(unittest.TestCase):
    def test_review_toy_without_replacement(self):
        # A has trips {yes, no}, B has {yes, yes}; two distinct trips both answer yes.
        owner = np.array([0, 0, 1, 1])
        member = np.array([[1, 0, 1, 1], [1, 0, 1, 1]], dtype=bool)
        like = distinct_assignments(member, owner, 2) / falling(np.array([2, 2]), 2)
        self.assertEqual(list(like / like.sum()), [0.0, 1.0])  # B certain (not 0.8)

    def test_matches_brute_force(self):
        rng = random.Random(3)
        for _ in range(200):
            owner = np.array(sorted(rng.randrange(3) for _ in range(9)))
            k = rng.randint(1, 3)
            member = np.array([[rng.random() < .5 for _ in range(9)] for _ in range(k)])
            got = distinct_assignments(member, owner, 3)
            for u in range(3):
                trips = np.flatnonzero(owner == u)
                brute = sum(all(member[i, t] for i, t in enumerate(tup)) for tup in itertools.permutations(trips, k))
                self.assertEqual(brute, got[u])


if __name__ == "__main__":
    unittest.main()
