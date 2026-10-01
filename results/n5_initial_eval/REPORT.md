# Initial evaluation of N5 A/B

## Design and validation

64 candidate trajectories per run; seeds 1–5; budgets 0–4; six zones. Nested pools contain 6, 36, 66 and 186 queries. Original sampled fixes are evaluated without resampling. The primary setting uses zone half-side 150 m and relative gap 120 s; the real-data sensitivity setting uses half-side 500 m and gap 900 s. Both parameters change together, so this is not a factorial ablation.

The pools are anchored on the known candidate universe. These are closed-world, finite-pool optima, not held-out population estimates. The rank-skewed prior is hypothetical (weights proportional to 1/rank over sorted candidate IDs), not learned from history. Dwell is excluded because it lacks a circuit.

Completed/replayed runs: 34/35. Recorded settings: 1360. Bound violations: 0. Tree replay checks the semantic answers, branch membership, path budget and terminal guessing reward. Checks also cover nested-pool and budget monotonicity and policy-equivalence ceilings.

## B=4, uniform prior

Values are mean optimal guessing success across completed seeds; brackets show min–max, not confidence intervals. Prior guessing success is 1/64 = 1.5625%; the ideal A bound is 16/64 = 25%.

| Source / setting | Completed seeds | Visit | + ordering | + relative time | + avoidance |
|---|---:|---:|---:|---:|---:|
| synthetic / primary | 4/5 | 12.50% [9.38–14.06] | 25.00% [25.00–25.00] | 25.00% [25.00–25.00] | 25.00% [25.00–25.00] |
| porto / primary | 5/5 | 13.12% [9.38–21.88] | 13.44% [9.38–21.88] | 13.44% [9.38–21.88] | 13.75% [9.38–23.44] |
| porto / wide_long | 5/5 | 19.06% [14.06–25.00] | 22.19% [18.75–25.00] | 22.19% [18.75–25.00] | 22.50% [18.75–25.00] |
| geolife / primary | 5/5 | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] |
| geolife / wide_long | 5/5 | 10.31% [9.38–10.94] | 11.56% [9.38–14.06] | 11.56% [9.38–14.06] | 11.56% [9.38–14.06] |
| tdrive / primary | 5/5 | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] | 8.75% [7.81–10.94] |
| tdrive / wide_long | 5/5 | 10.00% [7.81–10.94] | 10.31% [7.81–12.50] | 10.31% [7.81–12.50] | 10.31% [7.81–12.50] |

## Paired capability increments at B=4

Each comparison retains exactly the same candidates, prior and geometry. The larger family also contains more queries, so this measures the benefit of access to the expanded finite pool, not a query-count-matched ablation.

| Setting / prior | Ordering: improved runs | Timing: improved runs | Avoidance: improved runs |
|---|---:|---:|---:|
| primary / uniform | 1/15 | 0/15 | 1/15 |
| primary / rank_skewed_sensitivity | 2/15 | 0/15 | 0/15 |
| wide_long / uniform | 8/15 | 0/15 | 1/15 |
| wide_long / rank_skewed_sensitivity | 9/15 | 0/15 | 1/15 |

## Bound tightness and computation

Real-data full-pool B=4 uniform success reaches 31.2–100.0% of the ideal bound (mean 50.4%). A loose bound is valid but not predictive of achievable disclosure in this restricted policy pool.

With 64 candidates, the chosen skewed prior has p0 approximately 21.08%. The A bound saturates at 1 from B=3, so it gives no nontrivial upper bound there; finite-pool optimisation can remain informative.

Guessing solver time per setting: median 0.000643 s, maximum 9.4807 s. Maximum explored guessing states: 131413. Sum of run wall times (includes replay): 396.77 s. These Python optimisation timings are not cryptographic proving times; runs use a 200,000-state guard and a 120 s process timeout.

## Interpretation and limits

A is numerically consistent with all tested ideal transcripts; these experiments do not prove adaptive cryptographic simulation, PQ security or wallet enforcement. B quantifies restricted-pool disclosure and does not imply every added capability strictly increases it. Sparse/constant policy answers, equivalence classes and the query budget can all limit gains. Five seeds and 64 candidates are preliminary evidence.

Next: inspect separating policies and constant-query rates, expand geometries and budgets, compare matched query counts, and evaluate historical priors. The real-view theorem premises remain a separate task.

Reproduce from `Codebase/code`:

```sh
PYTHONPATH=python python3 -m zkmob.n5_initial_eval
PYTHONPATH=python python3 -m zkmob.n5_initial_report
```

Artifacts: `all_results.csv`, `summary.csv`, `run_status.json`, per-run CSV/JSON/log files, and `primary_curves.png` / `primary_curves.pdf`.

## Incomplete runs

Failed runs are excluded from means, not replaced by approximate optima. The synthetic summary is therefore completion-conditioned and may underrepresent harder instances.
- synthetic / primary / seed 5: exact search exceeded the 200,000-state guard; see its log.
