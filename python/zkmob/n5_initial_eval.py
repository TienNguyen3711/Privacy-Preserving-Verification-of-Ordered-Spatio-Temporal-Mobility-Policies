"""Run and independently replay a multi-seed initial N5 A/B evaluation.

From code/: PYTHONPATH=python python3 -m zkmob.n5_initial_eval
Outputs stay separate from the earlier pilot. No cryptographic proof is run.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np

from .policy import evaluate, policy_from_dict
from .trajectory import Point

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/n5_initial_eval"


def replay(path, rows):
    data = json.loads(path.read_text())
    traces = [[Point(*p) for p in t["points"]] for t in data["candidates"]]
    matrices = {family: np.array([[evaluate(policy_from_dict(s), t) for t in traces] for s in specs])
                for family, specs in data["policy_pools"].items()}
    lookup = {(r["prior"], r["family"], int(r["budget"])): r for r in rows}
    for run in data["runs"]:
        weights = np.array(run["weights"])
        for cert in run["trees"]:
            r = lookup[run["prior"], cert["family"], cert["budget"]]
            A = matrices[cert["family"]]
            for kind in ("guessing_tree", "capacity_tree"):
                leaves = set()
                for truth in range(len(traces)):
                    node, depth = cert[kind], 0
                    while node["query"] is not None:
                        node = node["yes"] if A[node["query"], truth] else node["no"]
                        depth += 1
                    assert depth <= cert["budget"] and truth in node["candidates"]
                    leaves.add(tuple(node["candidates"]))
                if kind == "guessing_tree":
                    score = sum(max(weights[list(leaf)]) for leaf in leaves)
                    assert abs(score - float(r["optimal_guess"])) < 1e-12
                    assert score <= float(r["ideal_guess_bound"]) + 1e-12
                    assert score <= float(r["equivalence_guess_ceiling"]) + 1e-12
                else:
                    assert len(leaves) == int(r["capacity_leaves"])
                    assert len(leaves) <= min(2 ** cert["budget"], int(r["equivalence_classes"]))
    # Verify monotonicity for the nested family and budget comparisons.
    families = list(data["policy_pools"])
    budgets = sorted({int(r["budget"]) for r in rows})
    for run in data["runs"]:
        for field in ("optimal_guess", "capacity_leaves"):
            grid = np.array([[float(lookup[run["prior"], f, b][field]) for b in budgets] for f in families])
            assert np.all(np.diff(grid, axis=0) >= -1e-12)
            assert np.all(np.diff(grid, axis=1) >= -1e-12)


def write_csv(path, rows):
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    all_rows, status = [], []
    env = dict(os.environ, PYTHONPATH=str(ROOT / "python"))
    # Fixed exploratory design: joint geometry/time sensitivity, not a factorial ablation.
    for source in ("synthetic", "porto", "geolife", "tdrive"):
        scenarios = [("primary", 150, 120)]
        if source != "synthetic":
            scenarios.append(("wide_long", 500, 900))
        for scenario, half, gap in scenarios:
            for seed in range(1, 6):
                name = f"{source}_{scenario}_seed{seed}"
                target = OUT / f"{name}.csv"
                cmd = [sys.executable, "-m", "zkmob.n5_capacity", "--candidates", "64", "--zones", "6",
                       "--budgets", "0", "1", "2", "3", "4", "--seed", str(seed),
                       "--half-side", str(half), "--gap", str(gap), "--out", str(target)]
                if source != "synthetic":
                    cmd += ["--input", str(ROOT / f"work/n1_{source}.jsonl")]
                start = time.perf_counter()
                entry = dict(source=source, scenario=scenario, seed=seed, command=cmd)
                try:
                    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
                    (OUT / f"{name}.log").write_text(proc.stdout + proc.stderr)
                    if proc.returncode:
                        raise RuntimeError(f"runner exit {proc.returncode}; see log")
                    with target.open() as fh:
                        rows = list(csv.DictReader(fh))
                    replay(target.with_suffix(".json"), rows)
                    for r in rows:
                        r.update(source=source, scenario=scenario, half_side_m=half, gap_s=gap)
                    all_rows.extend(rows)
                    entry["status"] = "completed_and_replayed"
                except (subprocess.TimeoutExpired, RuntimeError, AssertionError) as exc:
                    entry.update(status="failed", error=repr(exc))
                entry["wall_s"] = time.perf_counter() - start
                status.append(entry)
                (OUT / "run_status.json").write_text(json.dumps(status, indent=2) + "\n")
                print(name, entry["status"], f"{entry['wall_s']:.2f}s", flush=True)
    if all_rows:
        write_csv(OUT / "all_results.csv", all_rows)
        summaries = []
        keys = sorted({(r["source"], r["scenario"], r["prior"], r["family"], int(r["budget"])) for r in all_rows})
        for source, scenario, prior, family, budget in keys:
            group = [r for r in all_rows if (r["source"], r["scenario"], r["prior"], r["family"], int(r["budget"])) ==
                     (source, scenario, prior, family, budget)]
            g = np.array([float(r["optimal_guess"]) for r in group])
            summary = dict(source=source, scenario=scenario, prior=prior, family=family, budget=budget,
                           completed_seeds=len(group), guess_mean=float(g.mean()), guess_min=float(g.min()),
                           guess_max=float(g.max()), ideal_bound=float(group[0]["ideal_guess_bound"]),
                           guessing_s_mean=float(np.mean([float(r["guessing_s"]) for r in group])),
                           guessing_s_max=max(float(r["guessing_s"]) for r in group))
            summaries.append(summary)
        write_csv(OUT / "summary.csv", summaries)
    failed = sum(r["status"] == "failed" for r in status)
    print(f"Finished: {len(all_rows)} rows, {len(status)-failed}/{len(status)} runs completed and replayed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
