import unittest

import numpy as np

from zkmob.leakage import exact_partition
from zkmob.n5_length_classes import length_class


class LengthClassTest(unittest.TestCase):
    def test_schemes(self):
        self.assertEqual(length_class(41, "none"), 0)
        self.assertEqual(length_class(41, "exact"), 41)
        self.assertEqual(length_class(41, "pow2"), 64)
        self.assertEqual(length_class(64, "pow2"), 64)
        self.assertEqual(length_class(5, "pow2"), 32)

    def test_charge_all_bound_holds_per_class(self):
        rng = np.random.default_rng(0)
        A = rng.random((60, 300)) < 0.4
        cls = rng.integers(0, 4, 300)
        for b in (1, 2, 3):
            cells = sum(len(exact_partition(A[:, cls == c], "adaptive", b, "all", 60)) for c in range(4))
            self.assertLessEqual(np.log2(cells) - np.log2(4), b + 1e-9)


if __name__ == "__main__":
    unittest.main()
