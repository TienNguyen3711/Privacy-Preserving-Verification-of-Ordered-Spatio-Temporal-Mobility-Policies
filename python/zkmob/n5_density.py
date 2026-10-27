"""Candidate-route density for the C3 datasets (added 26 Oct 2026).

Explains why T-Drive is not used for C3: in the 120 represented ticks of the
evaluation-period trips, how many recorded fixes and distinct 250 m cells does
a candidate route hold? Settings match `n5_bounds.py` (Porto: first 60,000
rows, 15 s ticks, central 10 km window; GeoLife: 40 users with the most files,
30 s ticks; T-Drive: all taxis, 30 s ticks, GeoLife's Beijing window).

    PYTHONPATH=python python3 -m zkmob.n5_density
writes results/n5_c3_density.csv
"""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

from .datasets import geolife_files, load_geolife, load_porto, load_tdrive, time_split
from .n5_real import BEIJING_WIN, PORTO_WIN, dedupe, to_cells

LENGTH = 120


def stats(name, trips, win, period):
    _, ev = time_split(trips)
    cells, kept = to_cells(ev, win, period, LENGTH)
    fixes = [sum(1 for p in t.points if p.t <= (LENGTH - 1) * period) for t in kept]
    distinct = [len({tuple(c) for c in row if c[0] >= 0}) for row in cells]
    row = {"dataset": name, "tick_s": period, "represented_trips": len(kept),
           "distinct_sequences": len(dedupe(cells)),
           "median_recorded_fixes": float(np.median(fixes)),
           "median_distinct_cells": float(np.median(distinct))}
    print(row)
    return row


def main() -> None:
    rows = [stats("porto", load_porto(max_rows=60_000), PORTO_WIN, 15)]
    files = geolife_files()
    users = sorted(files, key=lambda u: -len(files[u]))[:40]
    rows.append(stats("geolife", load_geolife(users=users), BEIJING_WIN, 30))
    rows.append(stats("tdrive", load_tdrive(), BEIJING_WIN, 30))
    out = Path("results/n5_c3_density.csv")
    with open(out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
