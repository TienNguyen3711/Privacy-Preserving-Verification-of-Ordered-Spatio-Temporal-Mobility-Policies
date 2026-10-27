"""C3 (N5) on T-Drive, added 26 Oct 2026 after the supervisor review.

Runs the three C3 experiments of the paper on T-Drive with the settings of the
12 October 2026 rerun for Porto and GeoLife, without touching their results:
* unbudgeted identification (`n5_real.run_scope`): seed 1, pool 600, 40 targets,
  up to 40 queries, zones of 250/500/1,000 m;
* leakage versus charging rule (`n5_bounds.experiment_a`): exact, pool 400;
* identity leakage over K trips (`n5_bounds.experiment_b`), per trace and per
  device, 200 trials.
T-Drive is Beijing taxi data sampled about every 300 s; it uses GeoLife's
central 30 x 30 km window and 30 s ticks (120 ticks = 1 h, carry-forward).
Identities are taxi IDs, a proxy for one device, as for Porto.

    PYTHONPATH=python python3 -m zkmob.n5_tdrive [--taxis N]
"""

from __future__ import annotations

import argparse

from .datasets import load_tdrive
from .n5_bounds import _setup, experiment_a, experiment_b, write
from .n5_real import BEIJING_WIN, run_scope

PERIOD, LENGTH = 30, 120


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--taxis", type=int, default=0, help="taxis loaded (0 = all 10,357)")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    trips = load_tdrive(max_taxis=a.taxis or None, seed=a.seed)
    print(f"T-Drive: {len(trips)} trips")

    print("Unbudgeted identification")
    rows = run_scope("city", "tdrive", trips, BEIJING_WIN, PERIOD, LENGTH, 2_000, (1, 2, 4), 40, 40, 600, a.seed)
    write(rows, "results/n5_real_tdrive.csv")

    cells, kept, pool = _setup(trips, BEIJING_WIN, PERIOD, LENGTH, a.seed, 400)
    print("Experiment A: leakage versus charging rule")
    write(experiment_a("tdrive", cells, pool, a.seed), "results/n5_bounds_charging_tdrive.csv")
    print("Experiment B: per trace")
    write(experiment_b("tdrive", cells, kept, pool, 200, a.seed), "results/n5_bounds_users_tdrive.csv")
    print("Experiment B: per device")
    write(experiment_b("tdrive", cells, kept, pool, 200, a.seed, device=True), "results/n5_bounds_users_device_tdrive.csv")


if __name__ == "__main__":
    main()
