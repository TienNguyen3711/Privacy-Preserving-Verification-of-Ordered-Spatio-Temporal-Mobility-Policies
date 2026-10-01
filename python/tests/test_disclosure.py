"""Independent small-tree enumeration and semantic fixtures for N5 A/B."""

import itertools
import math
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zkmob.bridge import to_circuit_policy
from zkmob.disclosure import DisclosureSolver, SearchLimitExceeded, guessing_bound, optimal_disclosure
from zkmob.n5_capacity import _prepare_analysis, analyse, nested_policy_pools
from zkmob.policy import Box, evaluate, policy_from_dict
from zkmob.trajectory import Point


def all_partitions(A, ids, budget):
    """Brute enumerate every legal tree's leaves; no optimisation/memoisation."""
    yield (ids,)
    if budget == 0:
        return
    for row in A:
        left = tuple(i for i in ids if not row[i])
        right = tuple(i for i in ids if row[i])
        if left and right:
            for a, b in itertools.product(all_partitions(A, left, budget - 1),
                                          all_partitions(A, right, budget - 1)):
                yield a + b


class GuessingBound(unittest.TestCase):
    def test_uniform_skewed_and_saturation(self):
        self.assertEqual(guessing_bound(1 / 2000, 4), 16 / 2000)
        self.assertEqual(guessing_bound(.3, 1), .6)
        self.assertEqual(guessing_bound(.3, 2), 1)
        self.assertEqual(guessing_bound(.2, 0), .2)
        self.assertEqual(guessing_bound(1e-300, 10000), 1)

    def test_bad_bounds(self):
        for p, b in [(0, 1), (-.1, 2), (1.1, 2), (math.nan, 2), (.1, -1), (.1, 1.5), (.1, True)]:
            with self.subTest(p=p, b=b), self.assertRaises(ValueError):
                guessing_bound(p, b)


class ExactDisclosure(unittest.TestCase):
    def test_reusable_budgets_and_exact_weight_pruning(self):
        rng = np.random.default_rng(402)
        for _ in range(30):
            A = rng.integers(0, 2, (5, 6))
            # Include zeros, equal and near-equal masses to exercise pruning ties.
            p = rng.choice([0., .1, np.nextafter(.1, 1.), .5], size=6)
            if not p.any():
                p[0] = 1
            p /= p.sum()
            for objective in ('guessing', 'leaves'):
                solver = DisclosureSolver(A, p, objective)
                for b in [2, 0, 1, 3, 2]:
                    partitions = list(all_partitions(A, tuple(range(6)), b))
                    scores = [(sum(max(p[list(leaf)]) for leaf in tree), len(tree)) for tree in partitions]
                    best = max(scores, key=lambda x: x if objective == 'guessing' else (x[1], x[0]))
                    result = solver.solve(b)
                    self.assertAlmostEqual(result.posterior_guess, best[0])
                    if objective == 'leaves':
                        self.assertEqual(result.leaves, best[1])
                self.assertEqual(solver.solve(2).states, 0)

    def test_atom_compression_preserves_original_ids(self):
        A = np.array([[0, 0, 1, 1], [1, 1, 0, 0]])
        solver = DisclosureSolver(A, [.1, .4, .3, .2])
        self.assertEqual(len(solver.atoms), 2)
        self.assertEqual(len(solver.queries), 1)
        result = solver.solve(1)
        self.assertEqual(result.tree.no.candidates, (0, 1))
        self.assertEqual(result.tree.yes.candidates, (2, 3))
        self.assertAlmostEqual(result.posterior_guess, .7)

    def test_matches_exhaustive_trees_under_nonuniform_priors(self):
        rng = np.random.default_rng(91)
        for _ in range(20):
            A = rng.integers(0, 2, (4, 5)).astype(bool)
            p = rng.random(5)
            p /= p.sum()
            for budget in range(3):
                partitions = list(all_partitions(A, tuple(range(5)), budget))
                best = max(sum(max(p[list(leaf)]) for leaf in tree) for tree in partitions)
                result = optimal_disclosure(A, budget, p)
                self.assertAlmostEqual(result.posterior_guess, best)
                capacity = optimal_disclosure(A, budget, objective="leaves")
                self.assertEqual(capacity.leaves, max(map(len, partitions)))
                self.assertAlmostEqual(capacity.posterior_guess, capacity.leaves / 5)
                self.assertLessEqual(result.posterior_guess, guessing_bound(max(p), budget) + 1e-12)

    def test_tree_replay_and_mass_accounting(self):
        A = np.array([[0, 0, 1, 1], [0, 1, 0, 1]], dtype=bool)
        p = np.array([.55, .25, .15, .05])
        result = optimal_disclosure(A, 2, p)
        leaves = {}
        for truth in range(4):
            node, depth = result.tree, 0
            while node.query is not None:
                node = node.yes if A[node.query, truth] else node.no
                depth += 1
            self.assertIn(truth, node.candidates)
            self.assertLessEqual(depth, 2)
            leaves[node.candidates] = max(p[list(node.candidates)])
        self.assertEqual(len(leaves), result.leaves)
        self.assertAlmostEqual(sum(leaves.values()), result.posterior_guess)
        self.assertAlmostEqual(result.posterior_guess, 1)

    def test_empty_pool_duplicates_and_equivalence_ceiling(self):
        empty = optimal_disclosure(np.empty((0, 3), dtype=bool), 100, [.6, .3, .1])
        self.assertEqual(empty.leaves, 1)
        self.assertEqual(empty.posterior_guess, .6)
        A = np.array([[0, 0, 1, 1], [0, 0, 1, 1], [1, 1, 0, 0], [1, 1, 1, 1]])
        result = optimal_disclosure(A, 100, [.5, .1, .3, .1])
        self.assertEqual(result.equivalence_classes, 2)
        self.assertEqual(result.leaves, 2)
        self.assertAlmostEqual(result.posterior_guess, .8)
        self.assertAlmostEqual(result.equivalence_guess_ceiling, .8)

    def test_zero_mass_and_unnormalised_prior(self):
        A = np.array([[0, 0, 1]])
        self.assertAlmostEqual(optimal_disclosure(A, 1, [9, 0, 1]).posterior_guess, 1)
        self.assertAlmostEqual(optimal_disclosure(A, 0, [9, 0, 1]).posterior_guess, .9)

    def test_singleton_answer_is_not_pointwise_safe(self):
        A = np.zeros((1, 2000), dtype=bool)
        A[0, 0] = True
        result = optimal_disclosure(A, 1)
        self.assertEqual(result.tree.yes.candidates, (0,))
        self.assertAlmostEqual(result.posterior_guess, 2 / 2000)
        self.assertAlmostEqual(result.min_entropy_leakage_bits, 1)

    def test_limits_fail_explicitly(self):
        with self.assertRaises(SearchLimitExceeded):
            optimal_disclosure(np.array([[0, 1]]), 1, max_states=1)
        for matrix, prior in [(np.array([[0, 2]]), None), (np.empty((2, 0)), None),
                              (np.array([[0, 1]]), [0, 0]), (np.array([[0, 1]]), [-1, 2]),
                              (np.array([[0, 1]]), [math.nan, 1]), (np.array([[0, 1]]), [1])]:
            with self.subTest(matrix=matrix, prior=prior), self.assertRaises(ValueError):
                optimal_disclosure(matrix, 1, prior)


class PolicyFamilyAnalysis(unittest.TestCase):
    def setUp(self):
        self.zones = [Box(x, x, 0, 0) for x in (0, 10, 20)]
        self.traces = [[Point(0, 0, 0), Point(10, 0, 10)],
                       [Point(10, 0, 0), Point(0, 0, 10)],
                       [Point(0, 0, 0), Point(10, 0, 100)],
                       [Point(0, 0, 0), Point(20, 0, 5), Point(10, 0, 10)]]

    def test_nested_families_distinguish_order_and_time(self):
        pools = nested_policy_pools(self.zones, gap_s=20)
        previous = []
        capacities = []
        for specs in pools.values():
            self.assertEqual(specs[:len(previous)], previous)
            policies = [policy_from_dict(s) for s in specs]
            for pol in policies:
                to_circuit_policy(pol)  # default families are in the circuit language
            A = np.array([[evaluate(p, t) for t in self.traces] for p in policies])
            capacities.append(optimal_disclosure(A, 3).leaves)
            previous = specs
        self.assertEqual(capacities, [2, 3, 4, 4])

    def test_runner_labels_dwell_and_bounds(self):
        pools = nested_policy_pools(self.zones, gap_s=20, dwell_s=5)
        rows, trees = analyse(self.traces, pools, [0, 1, 2], [5, 3, 1, 1], 10000)
        self.assertEqual(len(rows), 15)
        self.assertEqual(len(trees), 15)
        self.assertTrue(all(r["within_bound"] for r in rows))
        for r in rows:
            self.assertEqual(r["circuit_supported"], r["family"] != "with_dwell_reference_only")

    def test_shared_analysis_does_not_reuse_wrong_prior(self):
        pools = nested_policy_pools(self.zones, gap_s=20)
        prepared = _prepare_analysis(self.traces, pools, 10000)
        analyse(self.traces, pools, [0, 1, 2], None, 10000, prepared)
        shared, _ = analyse(self.traces, pools, [0, 1, 2], [5, 3, 1, 1], 10000, prepared)
        fresh, _ = analyse(self.traces, pools, [0, 1, 2], [5, 3, 1, 1], 10000)
        for a, b in zip(shared, fresh):
            self.assertAlmostEqual(a['optimal_guess'], b['optimal_guess'])
            self.assertEqual(a['capacity_leaves'], b['capacity_leaves'])
            self.assertTrue(a['capacity_reused'])
            self.assertEqual(a['capacity_states'], 0)


if __name__ == "__main__":
    unittest.main()
