# Exact solver B optimisation

The optimised solver preserves exact finite-pool optimisation. It uses bitsets over policy-equivalence classes, duplicate/complement query removal, memoisation across budgets and admissible branch-and-bound. Pruning compares integer representations of the normalised floating-point prior, not rounded branch sums.

The runner also shares policy evaluations and capacities across nested pools/priors; uniform guessing reuses capacity. These extra runner savings are not included in the fresh-solver benchmark below.

## Validation

- 34 Python tests pass, including independent exhaustive-tree checks with skewed, zero and near-tied prior masses, both objectives and non-monotonic budget order.
- All 1,360 completed initial settings match archived probability results within 1e-12 and match capacity exactly. New weighted and capacity trees were replayed against the original answer matrices.
- The previously failed synthetic seed 5 now completes all 40 settings under the same 200,000-state guard. Its exported trees also pass independent semantic replay.
- Historical initial-evaluation artifacts remain unchanged. The original solver is archived under python/benchmarks only.

## Fresh solver timings

Identical saved matrices, B=4, full policy pool, three repetitions; table reports median times. Matrix construction and prior-run cache reuse are excluded. These are optimisation times, not proof-generation times.

| Input | Prior | Old (ms) | New (ms) | Speedup | Old/new states |
|---|---|---:|---:|---:|---:|
| synthetic_primary_seed3 | uniform | 9111.884 | 2.064 | 4415.2x | 131413 / 31 |
| synthetic_primary_seed3 | rank_skewed_sensitivity | 9228.455 | 5.297 | 1742.2x | 131413 / 120 |
| porto_wide_long_seed3 | uniform | 2481.719 | 0.899 | 2760.7x | 24213 / 31 |
| porto_wide_long_seed3 | rank_skewed_sensitivity | 2465.874 | 0.898 | 2744.6x | 24213 / 31 |
| geolife_wide_long_seed2 | uniform | 33.791 | 0.463 | 73.0x | 273 / 43 |
| geolife_wide_long_seed2 | rank_skewed_sensitivity | 33.937 | 0.657 | 51.6x | 273 / 64 |
| tdrive_primary_seed1 | uniform | 10.477 | 0.431 | 24.3x | 81 / 47 |
| tdrive_primary_seed1 | rank_skewed_sensitivity | 10.729 | 0.435 | 24.7x | 81 / 47 |

Large speedups occur where a good tree reaches an admissible ceiling early. They are instance-specific: the worst-case problem remains exponential. Returned trees can differ on tied optima. The state guard is cumulative per reusable solver instance and still raises on exhaustion; no approximate fallback was introduced.

## Reproduce

From Codebase/code:

```sh
PYTHONPATH=python python3 -m unittest discover -s python/tests -q
PYTHONPATH=python python3 python/benchmarks/benchmark_disclosure.py
PYTHONPATH=python python3 -m zkmob.n5_capacity --candidates 64 --zones 6 --budgets 0 1 2 3 4 --seed 5 --out results/n5_optimized/synthetic_seed5.csv
```

This optimisation changes neither the conditional premises of A nor the scope of B: a finite pool and a known candidate universe.
