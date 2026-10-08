"""Claim N1, robustness workload: zones and gaps not anchored on the trace.

`n1_export` anchors zones on two fixes of the trip and sets most gaps relative
to the observed time between them, so tight policies sit at the decision
boundary by construction (review, 7 Oct 2026). Here instead:

* zones are cells of a fixed city grid of side s in {100, 200, 400} m, chosen
  among the cells the trip enters (else almost every policy is trivially
  false); the order of the two cells is random, so "A, then B" may fail on
  order alone;
* the gap comes from a menu of round regulatory windows,
  {60, 120, 300, 600, 900, 1800} s, independent of the trip.

The batch format is that of `n1_export`, so `n1_real` (Rust) scores it
unchanged; the same seed samples the same trips.

    PYTHONPATH=python python3 -m zkmob.n1_grid_export --dataset geolife --trips 400
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterator, List

from .bridge import WORK, to_circuit_policy
from .datasets import Trip, describe, load
from .policy import Box, Ordered, Policy, Step, evaluate
from .trajectory import to_rows

CELL_SIDES = (100, 200, 400)
GAPS = (60, 120, 300, 600, 900, 1800)


def cell_box(cx: int, cy: int, s: int) -> Box:
    return Box(cx * s, cx * s + s - 1, cy * s, cy * s + s - 1)


def policies_for(trip: Trip, rng: random.Random, per_trip: int) -> Iterator[Dict]:
    for q in range(per_trip):
        s = rng.choice(CELL_SIDES)
        cells = sorted({(p.x // s, p.y // s) for p in trip.points})
        if len(cells) < 2:
            return
        ca, cb = rng.sample(cells, 2)
        gap = rng.choice(GAPS)
        pol = Policy([Ordered([Step(cell_box(*ca, s)), Step(cell_box(*cb, s), gap)])])
        meta = {"kind": "grid", "zone_half_m": s // 2, "cell_m": s}
        yield {"id": f"{trip.trip_id}#g{q}", "dataset": trip.dataset, **to_circuit_policy(pol),
               "expected": evaluate(pol, trip.points), "meta": meta}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, choices=["geolife", "tdrive", "porto"])
    ap.add_argument("--trips", type=int, default=400, help="trips sampled from the dataset")
    ap.add_argument("--per-trip", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    kw = {"geolife": {"max_files": 1_500, "seed": a.seed}, "tdrive": {"max_taxis": 300, "seed": a.seed},
          "porto": {"max_rows": 30_000}}[a.dataset]
    trips = load(a.dataset, **kw)
    rng = random.Random(a.seed)
    sample: List[Trip] = rng.sample(trips, min(a.trips, len(trips)))
    print(f"{a.dataset}: loaded {describe(trips)}; sampled {len(sample)} trips")

    out = Path(a.out) if a.out else WORK / f"n1_grid_{a.dataset}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    n = pos = 0
    with open(out, "w") as fh:
        for trip in sample:
            for item in policies_for(trip, rng, a.per_trip):
                item["points"] = to_rows(trip.points)
                fh.write(json.dumps(item) + "\n")
                n += 1
                pos += item["expected"]
    print(f"wrote {n} policies ({pos} hold, {n - pos} do not) to {out}")


if __name__ == "__main__":
    main()
