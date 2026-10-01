"""Claim N5 / baseline B5 on real data: what do repeated Boolean policy
outcomes reveal about one real trip?

Setting (same adversary as `leakage.py`): the verifier knows a candidate set
of routes and asks yes/no policy queries, each answered by an honest ZK
proof. We count how many candidates remain consistent with the answers.

Time-based split (no look-ahead): trips are ordered by start time; the first
70% are *history*, the last 30% the *evaluation period*.
* candidates = evaluation-period trips (the target is one of them);
* query zones are drawn uniformly, or in proportion to how many history
  trips visit each cell ("popular": the verifier asks about places people
  actually go, which it can learn from public/historical data).

Scopes:
* ``porto/city``   up to 2,000 taxi trips in central Porto (15 s sampling)
* ``geolife/<u>``  one GeoLife user's own trips: the candidate set is that
                   person's routine, the hardest case for privacy

Trips are placed on a fixed tick grid (period P, carry-forward, L ticks from
the trip start; ticks after the trip ends are padding that matches no zone)
and on 250 m cells, so queries can be evaluated vectorised; `test_policy.py`
checks the vectorised answers against `policy.evaluate`.

    PYTHONPATH=python python3 -m zkmob.n5_real
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from .datasets import Trip, geolife_files, load_geolife, load_porto, time_split
from .leakage import World, make_pool, simulate

PAD = -1_000_000  # cell coordinate used for ticks after the trip ends


@dataclass(frozen=True)
class Window:
    x0: int        # planar metres of the grid's lower-left corner
    y0: int
    grid: int      # cells per side
    cell_m: int = 250


PORTO_WIN = Window(10_000, 10_000, 40)          # central 10 km x 10 km
BEIJING_WIN = Window(15_000, 15_000, 120)       # central 30 km x 30 km


def to_cells(trips: Sequence[Trip], win: Window, period: int, length: int,
             min_ticks: int = 10) -> Tuple[np.ndarray, List[Trip]]:
    """(M, L, 2) cell array for the trips that stay inside the window."""
    rows, kept = [], []
    for tr in trips:
        ticks = min(length, tr.duration // period + 1)
        if ticks < min_ticks:
            continue
        cells = np.full((length, 2), PAD, dtype=np.int32)
        j, ok = 0, True
        for k in range(ticks):
            while j + 1 < len(tr.points) and tr.points[j + 1].t <= k * period:
                j += 1
            p = tr.points[j]
            cx, cy = (p.x - win.x0) // win.cell_m, (p.y - win.y0) // win.cell_m
            if not (0 <= cx < win.grid and 0 <= cy < win.grid):
                ok = False
                break
            cells[k] = (cx, cy)
        if ok:
            rows.append(cells)
            kept.append(tr)
    arr = np.stack(rows) if rows else np.zeros((0, length, 2), dtype=np.int32)
    return arr, kept


def dedupe(cands: np.ndarray) -> np.ndarray:
    """Drop candidates with identical cell sequences (indistinguishable by
    any cell-aligned query, so 'identified' would be unreachable)."""
    _, idx = np.unique(cands.reshape(cands.shape[0], -1), axis=0, return_index=True)
    return cands[np.sort(idx)]


def popularity(cands: np.ndarray, grid: int) -> np.ndarray:
    """Number of trips visiting each cell (+1 smoothing)."""
    w = np.ones((grid, grid), dtype=np.float64)
    for tr in cands:
        v = tr[tr[:, 0] != PAD]
        for cx, cy in {(int(a), int(b)) for a, b in v}:
            w[cx, cy] += 1
    return w


def run_scope(name: str, dataset: str, trips: Sequence[Trip], win: Window, period: int, length: int,
              max_cands: int, sides: Sequence[int], trials: int, max_q: int, pool_size: int, seed: int) -> List[Dict]:
    hist, evalp = time_split(trips)
    h_cells, _ = to_cells(hist, win, period, length)
    e_cells, _ = to_cells(evalp, win, period, length)
    e_cells = dedupe(e_cells)
    if len(e_cells) > max_cands:
        e_cells = e_cells[np.sort(np.random.default_rng(seed).choice(len(e_cells), max_cands, replace=False))]
    M = len(e_cells)
    if M < 10 or len(h_cells) < 10:
        print(f"  {name}: skipped (history {len(h_cells)}, candidates {M})")
        return []
    w = World(grid=win.grid, cell_m=win.cell_m, steps=length, step_s=period, n_candidates=M)
    weights = popularity(h_cells, win.grid)
    gaps = tuple(max(1, g // period) for g in (300, 600, 1200, 2400))
    rows = []
    for side in sides:
        for pool_kind in ("popular", "uniform"):
            pool = make_pool(w, side, pool_size, seed + side, weights if pool_kind == "popular" else None, gaps)
            for attacker in ("random", "adaptive"):
                r = simulate(e_cells, pool, attacker, max_q, trials, seed + 7)
                for k in range(max_q + 1):
                    col = r[:, k]
                    rows.append({"dataset": dataset, "scope": name, "history_trips": len(h_cells), "candidates": M,
                                 "pool": pool_kind, "zone_side_m": side * win.cell_m, "attacker": attacker,
                                 "queries": k, "median_remaining": float(np.median(col)),
                                 "p10_remaining": float(np.percentile(col, 10)),
                                 "p90_remaining": float(np.percentile(col, 90)),
                                 "mean_remaining": float(col.mean()), "share_identified": float(np.mean(col == 1))})
                ident = lambda q: np.mean(r[:, q] == 1)  # noqa: E731
                print(f"  {name:>12} M={M:>4} side={side * win.cell_m:>4} m {pool_kind:>7} {attacker:>8}: "
                      f"median left after 5/10/20 = {np.median(r[:, 5]):.0f}/{np.median(r[:, 10]):.0f}/"
                      f"{np.median(r[:, 20]):.0f}; identified after 10/20/40 = "
                      f"{ident(10):.0%}/{ident(20):.0%}/{ident(40):.0%}")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--porto-rows", type=int, default=60_000)
    ap.add_argument("--geolife-users", type=int, default=6, help="users with the most trajectory files")
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--max-q", type=int, default=40)
    ap.add_argument("--pool", type=int, default=600)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="results/n5_real.csv")
    a = ap.parse_args()
    common = dict(sides=(1, 2, 4), trials=a.trials, max_q=a.max_q, pool_size=a.pool, seed=a.seed)

    rows: List[Dict] = []
    print("Porto (city-wide candidate set)")
    rows += run_scope("city", "porto", load_porto(max_rows=a.porto_rows), PORTO_WIN, 15, 120, 2_000, **common)

    print("GeoLife (per-user candidate sets)")
    files = geolife_files()
    users = sorted(files, key=lambda u: -len(files[u]))[: a.geolife_users]
    for u in users:
        rows += run_scope(f"user{u}", "geolife", load_geolife(users=[u]), BEIJING_WIN, 30, 120, 2_000, **common)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {a.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
