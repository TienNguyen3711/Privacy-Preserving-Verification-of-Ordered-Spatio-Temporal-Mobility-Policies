"""A4 metadata: does raw STARK proving time reveal the policy outcome?

Input: results/a4_timing.csv from repeated `host` runs (zkvm/host, order of
the yes/no statements alternated with --reverse). For each outcome we report
proving-time mean/sd, receipt sizes and guest cycle counts, then:

* a two-sided permutation test on the difference of mean proving times;
* the accuracy of the best single-threshold classifier "outcome from time"
  (in-sample, so an optimistic estimate of what a timing observer achieves);
* whether the padded cycle count and receipt size differ between outcomes.

Small samples (tens of proofs) can show a difference but cannot prove its
absence; the report says which.

    PYTHONPATH=python python3 -m zkmob.a4_timing
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np


def best_threshold_accuracy(x: np.ndarray, y: np.ndarray) -> float:
    """Best in-sample accuracy of 'predict y=1 iff x > t' or 'iff x <= t'."""
    best = max(np.mean(y == 1), np.mean(y == 0))
    for t in np.unique(x):
        pred = x > t
        acc = max(np.mean(pred == (y == 1)), np.mean(pred != (y == 1)))
        best = max(best, acc)
    return float(best)


def permutation_p(a: np.ndarray, b: np.ndarray, reps: int = 20000, seed: int = 1) -> float:
    rng = np.random.default_rng(seed)
    obs = abs(a.mean() - b.mean())
    pool = np.concatenate([a, b])
    hits = 0
    for _ in range(reps):
        rng.shuffle(pool)
        if abs(pool[:len(a)].mean() - pool[len(a):].mean()) >= obs:
            hits += 1
    return (hits + 1) / (reps + 1)


def main(path: str = "results/a4_timing.csv", out: str = "results/a4_timing_summary.json") -> None:
    rows = list(csv.DictReader(open(path)))
    y = np.array([r["outcome"] == "true" for r in rows], dtype=int)
    t = np.array([float(r["prove_s"]) for r in rows])
    user = np.array([int(r["user_cycles"]) for r in rows])
    total = np.array([int(r["total_cycles"]) for r in rows])
    size = np.array([int(r["receipt_bytes"]) for r in rows])
    yes, no = t[y == 1], t[y == 0]
    summary = {
        "n_yes": int(len(yes)), "n_no": int(len(no)),
        "prove_s_yes_mean": float(yes.mean()), "prove_s_yes_sd": float(yes.std(ddof=1)),
        "prove_s_no_mean": float(no.mean()), "prove_s_no_sd": float(no.std(ddof=1)),
        "mean_diff_s": float(yes.mean() - no.mean()),
        "permutation_p": permutation_p(yes, no),
        "threshold_classifier_accuracy_in_sample": best_threshold_accuracy(t, y),
        "user_cycles_yes": sorted(set(user[y == 1].tolist())),
        "user_cycles_no": sorted(set(user[y == 0].tolist())),
        "padded_cycles_distinct": sorted(set(total.tolist())),
        "receipt_bytes_distinct": sorted(set(size.tolist())),
    }
    Path(out).write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:])
