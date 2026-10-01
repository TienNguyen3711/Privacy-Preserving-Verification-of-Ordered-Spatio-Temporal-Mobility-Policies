"""Claim N1 on real data: build the policy workload for `n1_real` (Rust).

For each sampled trip we draw two fixes i < j (t_j - t_i >= 60 s) and put
square zones A, B of half-side h around them. Three kinds of policy:

* ``tight``    "A, then B within f * (t_j - t_i)", f in {0.8, 0.9, 1.0, 1.1, 1.25}
               near the decision boundary, where time precision matters most;
* ``loose``    same zones, max_gap from {300, 600, 900, 1800} s
               (typical round-number regulatory windows);
* ``reversed`` "B, then A within 1.25 * (t_j - t_i)", which tests order.

Zones are trace-anchored so that both outcomes occur; the exact outcome is
computed by `policy.evaluate` and stored as ``expected`` (Rust re-checks it).

    PYTHONPATH=python python3 -m zkmob.n1_export --dataset geolife --trips 400
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterator, List

from .bridge import WORK, around, to_circuit_policy
from .datasets import Trip, describe, load
from .policy import Ordered, Policy, Step, evaluate
from .trajectory import to_rows

GAP_FACTORS = (0.8, 0.9, 1.0, 1.1, 1.25)
LOOSE_GAPS = (300, 600, 900, 1800)
HALF_SIDES = (50, 100, 200)


def policies_for(trip: Trip, rng: random.Random, per_trip: int) -> Iterator[Dict]:
    pts = trip.points
    kinds = ["tight", "tight", "loose", "reversed"]
    for q in range(per_trip):
        for _ in range(50):
            i = rng.randrange(len(pts) - 1)
            later = [j for j in range(i + 1, len(pts)) if 60 <= pts[j].t - pts[i].t <= 3_600]
            if later:
                j = rng.choice(later)
                break
        else:
            return
        dt = pts[j].t - pts[i].t
        h = rng.choice(HALF_SIDES)
        za, zb = around(pts[i], h), around(pts[j], h)
        kind = kinds[q % len(kinds)]
        meta = {"kind": kind, "zone_half_m": h, "i": i, "j": j, "observed_gap_s": dt}
        if kind == "tight":
            f = rng.choice(GAP_FACTORS)
            meta["gap_factor"] = f
            steps = [Step(za), Step(zb, max(1, round(dt * f)))]
        elif kind == "loose":
            steps = [Step(za), Step(zb, rng.choice(LOOSE_GAPS))]
        else:
            meta["gap_factor"] = 1.25
            steps = [Step(zb), Step(za, round(dt * 1.25))]
        pol = Policy([Ordered(steps)])
        yield {"id": f"{trip.trip_id}#{q}", "dataset": trip.dataset, **to_circuit_policy(pol),
               "expected": evaluate(pol, pts), "meta": meta}


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

    out = Path(a.out) if a.out else WORK / f"n1_{a.dataset}.jsonl"
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
