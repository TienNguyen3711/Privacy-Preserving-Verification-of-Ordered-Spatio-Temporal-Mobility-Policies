"""Reproducible A/B analysis on nested finite mobility-policy pools.

Default: a synthetic smoke experiment. --input accepts an existing N1 JSONL
export and evaluates its original fixes (no resampling or point truncation).
The candidate universe is known to the attacker; zones are anchored on that
universe. This is a closed-world analysis, NOT a history/evaluation split.
Uniform and explicitly hypothetical rank-skewed priors are compared.

Example (from code/):
  PYTHONPATH=python python3 -m zkmob.n5_capacity
  PYTHONPATH=python python3 -m zkmob.n5_capacity --input work/n1_porto.jsonl
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import replace
import hashlib
import json
import random
import time
from pathlib import Path

import numpy as np

from .disclosure import DisclosureSolver, guessing_bound, normalise_prior
from .policy import Box, evaluate, policy_from_dict
from .trajectory import Point, random_grid_walk


def nested_policy_pools(zones, gap_s=120, dwell_s=None):
    """Nested pools: an expressiveness comparison cannot remove old queries.

    All default queries compile through the existing circuit bridge.
    Optional dwell is reference-semantics-only, explicitly labelled below.
    """
    visit = [{"clauses": [{"visit": vars(z)}]} for z in zones]
    ordered, timed, avoid = [], [], []
    for i, a in enumerate(zones):
        for j, b in enumerate(zones):
            if i == j:
                continue
            steps = [{"zone": vars(a)}, {"zone": vars(b)}]
            ordered.append({"clauses": [{"ordered": steps}]})
            timed_steps = [{"zone": vars(a)}, {"zone": vars(b), "max_gap": gap_s}]
            timed.append({"clauses": [{"ordered": timed_steps}]})
            for k, z in enumerate(zones):
                if k not in (i, j):
                    avoid.append({"clauses": [{"ordered": timed_steps}, {"avoid": vars(z)}]})
    pools = {
        "visit": visit,
        "visit_ordered": visit + ordered,
        "visit_ordered_timed": visit + ordered + timed,
        "visit_ordered_timed_avoid": visit + ordered + timed + avoid,
    }
    if dwell_s is not None:
        pools["with_dwell_reference_only"] = pools["visit_ordered_timed_avoid"] + [
            {"clauses": [{"dwell": {"zone": vars(z), "min_s": dwell_s}}]} for z in zones]
    return pools


def load_candidates(path, count, seed):
    if path is None:
        rng = random.Random(seed)
        traces = [random_grid_walk(4, 100, 24, 30, rng) for _ in range(count)]
        return [f"synthetic:{i}" for i in range(count)], traces
    unique = {}
    with path.open() as fh:
        for line in fh:
            item = json.loads(line)
            key = item["id"].rsplit("#", 1)[0]
            if key not in unique:
                unique[key] = [Point(*p) for p in item["points"]]
    ids = sorted(random.Random(seed).sample(sorted(unique), min(count, len(unique))))
    if not ids:
        raise ValueError("input contains no candidates")
    return ids, [unique[i] for i in ids]


def _prepare_analysis(traces, pools, max_states):
    """Evaluate each distinct policy once, shared across nested pools/priors."""
    answers, prepared = {}, {}
    for family, specs in pools.items():
        rows = []
        for spec in specs:
            key = json.dumps(spec, sort_keys=True)
            if key not in answers:
                pol = policy_from_dict(spec)
                answers[key] = [evaluate(pol, tr) for tr in traces]
            rows.append(answers[key])
        matrix = np.asarray(rows, dtype=bool)
        prepared[family] = (matrix, DisclosureSolver(matrix, objective="leaves", max_states=max_states), {})
    return prepared


def analyse(traces, pools, budgets, prior, max_states, _prepared=None):
    """Return table rows and replayable optimal trees for a single prior."""
    p = normalise_prior(prior, len(traces))
    rows, certificates = [], []
    prepared = _prepared if _prepared is not None else _prepare_analysis(traces, pools, max_states)
    uniform = bool(np.all(p == p[0]))
    for family, specs in pools.items():
        A, capacity_solver, capacities = prepared[family]
        guessing_solver = None if uniform else DisclosureSolver(A, p, max_states=max_states)
        for budget in budgets:
            start = time.perf_counter()
            reused = budget in capacities
            if not reused:
                capacities[budget] = capacity_solver.solve(budget)
            cap = capacities[budget]
            capacity_s = time.perf_counter() - start
            start = time.perf_counter()
            result = replace(cap, objective="guessing", states=0) if uniform else guessing_solver.solve(budget)
            guessing_s = time.perf_counter() - start
            bound = guessing_bound(result.prior_guess, budget)
            row = {
                "family": family, "candidates": len(traces), "queries": len(specs),
                "budget": budget, "capacity_leaves": cap.leaves,
                "equivalence_classes": result.equivalence_classes,
                "prior_guess": result.prior_guess, "optimal_guess": result.posterior_guess,
                "ideal_guess_bound": bound,
                "equivalence_guess_ceiling": result.equivalence_guess_ceiling,
                "min_entropy_leakage_bits": result.min_entropy_leakage_bits,
                "search_states": result.states, "capacity_states": 0 if reused else cap.states,
                "capacity_s": capacity_s, "guessing_s": guessing_s,
                "capacity_reused": reused, "guessing_reused_uniform_capacity": uniform,
                "within_bound": result.posterior_guess <= bound + 1e-12,
                "method": "exact_finite_pool", "scope": "one_trace_one_verifier",
                "circuit_supported": family != "with_dwell_reference_only",
            }
            if not row["within_bound"]:
                raise AssertionError("ideal transcript bound violated")
            rows.append(row)
            certificates.append({"family": family, "budget": budget,
                                 "guessing_tree": result.tree.to_dict(),
                                 "capacity_tree": cap.tree.to_dict()})
    return rows, certificates


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path)
    ap.add_argument("--out", type=Path, help="CSV path; matching JSON manifest is also written")
    ap.add_argument("--candidates", type=int, default=24)
    ap.add_argument("--zones", type=int, default=4)
    ap.add_argument("--half-side", type=int, default=150)
    ap.add_argument("--gap", type=int, default=120)
    ap.add_argument("--budgets", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--include-dwell", action="store_true")
    ap.add_argument("--max-states", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    if min(args.candidates, args.zones, args.max_states) < 1 or min(args.half_side, args.gap, *args.budgets) < 0:
        ap.error("counts must be positive; distances, times and budgets must be non-negative")
    ids, traces = load_candidates(args.input, args.candidates, args.seed)
    coords = sorted({(p.x, p.y) for tr in traces for p in tr})
    picked = random.Random(args.seed + 1).sample(coords, min(args.zones, len(coords)))
    h = args.half_side
    zones = [Box(max(0, x - h), x + h, max(0, y - h), y + h) for x, y in picked]
    pools = nested_policy_pools(zones, args.gap, args.gap if args.include_dwell else None)
    priors = {"uniform": np.ones(len(traces)),
              "rank_skewed_sensitivity": 1.0 / np.arange(1, len(traces) + 1)}
    all_rows, runs = [], []
    prepared = _prepare_analysis(traces, pools, args.max_states)
    for name, prior in priors.items():
        rows, trees = analyse(traces, pools, args.budgets, prior, args.max_states, prepared)
        for row in rows:
            row.update(prior=name, seed=args.seed)
        all_rows.extend(rows)
        runs.append({"prior": name, "weights": normalise_prior(prior, len(traces)).tolist(), "trees": trees})
    source = args.input.stem if args.input else "synthetic"
    out = args.out or Path(f"results/n5_capacity_{source}.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(all_rows[0]))
        writer.writeheader()
        writer.writerows(all_rows)
    # Fixes and policy definitions allow independent replay without raw data files.
    manifest = {
        "schema_version": 1, "config": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest() if args.input else None,
        "scope": "closed_world_candidate_anchored_finite_pool",
        "cryptographic_simulation_verified": False,
        "skewed_prior_source": "hypothetical rank weights, not learned from history",
        "candidates": [{"id": i, "points": [[p.x, p.y, p.t] for p in tr]} for i, tr in zip(ids, traces)],
        "policy_pools": pools, "runs": runs,
    }
    out.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {out} and {out.with_suffix('.json')} ({len(all_rows)} exact finite-pool settings)")
    for row in all_rows:
        if row["budget"] == max(args.budgets):
            print(f"{row['prior']:>23} {row['family']:>30}: F={row['capacity_leaves']}, "
                  f"guess={row['optimal_guess']:.4f}, ideal bound={row['ideal_guess_bound']:.4f}")


if __name__ == "__main__":
    main()
