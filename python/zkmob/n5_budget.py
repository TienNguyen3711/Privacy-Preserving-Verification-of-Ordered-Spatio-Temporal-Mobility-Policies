"""N5 mechanism evaluation: anonymity set versus per-trace query budget B.

Same scopes, time split and query pools as `n5_real.py` (popularity-weighted
zones from the history period; candidates from the evaluation period). For
each budget B we report the remaining candidate set (the anonymity set) and
the leakage (mean Shannon bits with a 95% interval, min-entropy bits,
effective anonymity set; see `leakage.leakage_from_remaining`) against the
transcript-count bound (`leakage.transcript_bound_bits`), for two charging
rules:

* ``all``       every answer costs a slot (needs proofs of both outcomes:
                the rust scan circuit); this is the proposed mechanism
* ``yes_only``  only "holds" proofs cost a slot; "no" is free. This is what
                a nullifier on ordinary (true-only) proofs would enforce.

    PYTHONPATH=python python3 -m zkmob.n5_budget
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List

import numpy as np

from .datasets import geolife_files, load_geolife, load_porto, time_split
from .leakage import World, leakage_from_remaining, make_pool, simulate_budget, transcript_bound_bits
from .n5_real import BEIJING_WIN, PORTO_WIN, dedupe, popularity, to_cells

BUDGETS = (1, 2, 3, 4, 6, 8, 10, 15, 20)
MAX_TOTAL = 300  # cap on queries asked (matters only for charge="yes_only")


def scope_rows(name, dataset, trips, win, period, length, max_cands, sides, trials, pool_size, seed) -> List[Dict]:
    hist, evalp = time_split(trips)
    h_cells, _ = to_cells(hist, win, period, length)
    e_cells, _ = to_cells(evalp, win, period, length)
    e_cells = dedupe(e_cells)
    if len(e_cells) > max_cands:
        e_cells = e_cells[np.sort(np.random.default_rng(seed).choice(len(e_cells), max_cands, replace=False))]
    M = len(e_cells)
    if M < 10 or len(h_cells) < 10:
        return []
    w = World(grid=win.grid, cell_m=win.cell_m, steps=length, step_s=period, n_candidates=M)
    weights = popularity(h_cells, win.grid)
    gaps = tuple(max(1, g // period) for g in (300, 600, 1200, 2400))
    rows = []
    for side in sides:
        pool = make_pool(w, side, pool_size, seed + side, weights, gaps)
        for charge, attacker in (("all", "adaptive"), ("yes_only", "adaptive"), ("yes_only", "cheap")):
            r = simulate_budget(e_cells, pool, attacker, BUDGETS, trials, seed + 7, charge=charge, max_total=MAX_TOTAL)
            for bi, b in enumerate(BUDGETS):
                col = r[:, bi]
                met = leakage_from_remaining(col, M)
                rows.append({"dataset": dataset, "scope": name, "candidates": M, "zone_side_m": side * win.cell_m,
                             "charge": charge, "attacker": attacker, "budget": b,
                             "p10_remaining": float(np.percentile(col, 10)),
                             "p90_remaining": float(np.percentile(col, 90)), **met,
                             "bound_bits": transcript_bound_bits(b, MAX_TOTAL, charge),
                             "prior_bits": float(np.log2(M))})
            show = {b: np.median(r[:, BUDGETS.index(b)]) for b in (2, 4, 6, 10)}
            print(f"  {name:>9} M={M:>4} {side * win.cell_m:>4} m {charge:>8}/{attacker:<8} median left at "
                  + ", ".join(f"B={b}: {v:.0f}" for b, v in show.items()))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--pool", type=int, default=600)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="results/n5_budget.csv")
    a = ap.parse_args()
    common = dict(sides=(1, 4), trials=a.trials, pool_size=a.pool, seed=a.seed)
    rows: List[Dict] = []
    print("Porto (city-wide)")
    rows += scope_rows("city", "porto", load_porto(max_rows=60_000), PORTO_WIN, 15, 120, 2_000, **common)
    print("GeoLife (per user)")
    files = geolife_files()
    for u in sorted(files, key=lambda u: -len(files[u]))[:6]:
        rows += scope_rows(f"user{u}", "geolife", load_geolife(users=[u]), BEIJING_WIN, 30, 120, 2_000, **common)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {a.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
