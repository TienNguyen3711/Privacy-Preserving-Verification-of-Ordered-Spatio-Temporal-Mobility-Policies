"""C1 costs on the policy part alone, with the BL-clockDFA baseline (item 7).

`n1_fair` reports BL-bucket against the scan for the whole relation, where
the shared commitment and signature layer dilute every difference. This
module separates the policy part and adds the two other exact designs:

* ``selector``: the exact yes-only selector (proves only "holds");
* ``scan``: the proposed scan (proves either outcome);
* ``clock``: BL-clockDFA, a one-clock-per-step deterministic timed automaton
  evaluated per fix (rust ``automaton::ClockDfaCircuit``; either outcome,
  exact; per-item answers and costs from the ``n1_clock`` binary);
* ``bucket``: BL-bucket's DFA alone, and ``bucket_bound`` = the DFA plus the
  lower bound on binding its buckets to the committed fixes.

Per workload (trace-anchored ``n1_real``, city-grid ``n1_grid``), dataset and
bucket width w it writes the median per-item ratios

* ``scan_over_selector``: the price of "no" (exact, two-sided vs one-sided);
* ``clock_over_scan``: exact automaton vs the scan (no width dependence);
* ``bucket_over_scan`` and ``bucket_bound_over_scan``: the price of exactness
  against discretised time, on the policy part;
* ``e2e_bucket_over_scan`` and ``e2e_clock_over_scan``: the same with the
  commitment and signature layer added (``e2e_bucket`` equals ``ratio_e2e``
  of ``n1_fair``),

plus BL-bucket's error (any-fix) for the figure. No new measurements: the
BL-bucket, selector, scan and commitment counts are those in the adopted
``results/n1_real_*`` / ``n1_grid_*`` files.

    PYTHONPATH=python python3 -m zkmob.n1_policy_only [--sig 133931]
"""

from __future__ import annotations

import argparse
import csv
import statistics as st
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ("geolife", "porto", "tdrive")
WORKLOADS = {"n1_real": "n1_clock", "n1_grid": "n1_grid_clock"}


def rows_for(prefix: str, clock_prefix: str, ds: str, sig: int) -> list[dict]:
    clock = {r["id"]: r for r in csv.DictReader(open(ROOT / f"results/{clock_prefix}_{ds}.csv"))}
    by_w = defaultdict(list)
    for r in csv.DictReader(open(ROOT / f"results/{prefix}_{ds}.csv")):
        c = clock[r["id"]]
        assert c["n_points"] == r["n_points"] and c["truth"] == r["truth"], r["id"]
        assert c["clock_answer"] == r["truth"], f"{r['id']}: BL-clockDFA must be exact"
        by_w[int(r["bucket_s"])].append((r, int(c["clock_constraints"])))
    out = []
    for w in sorted(by_w, reverse=True):
        rs = by_w[w]
        sel = [int(r["ours_constraints"]) for r, _ in rs]
        scan = [int(r["ours_scan"]) for r, _ in rs]
        clk = [c for _, c in rs]
        dfa = [int(r["b3_constraints"]) for r, _ in rs]
        bound = [int(r["b3_constraints"]) + int(r["b3_binding_lb"]) for r, _ in rs]
        shared = [int(r["commit"]) + sig for r, _ in rs]
        ratio = lambda num, den: round(st.median(a / b for a, b in zip(num, den)), 4)  # noqa: E731
        plus = lambda xs: [x + s for x, s in zip(xs, shared)]  # noqa: E731
        err = sum((r["b3_any_answer"] == "true") != (r["truth"] == "true") for r, _ in rs)
        out.append({
            "workload": prefix, "dataset": ds, "bucket_s": w, "items": len(rs),
            "median_n": st.median(int(r["n_points"]) for r, _ in rs),
            "median_selector": st.median(sel), "median_scan": st.median(scan), "median_clock": st.median(clk),
            "median_bucket": st.median(dfa), "median_bucket_bound": st.median(bound),
            "scan_over_selector": ratio(scan, sel), "clock_over_scan": ratio(clk, scan),
            "bucket_over_scan": ratio(dfa, scan), "bucket_bound_over_scan": ratio(bound, scan),
            "e2e_bucket_over_scan": ratio(plus(bound), plus(scan)), "e2e_clock_over_scan": ratio(plus(clk), plus(scan)),
            "bucket_err_any": round(err / len(rs), 4),
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sig", type=int, default=133_931,
                    help="Lamport verification + 22 Merkle levels (constraints; as in n1_fair)")
    a = ap.parse_args()
    out = [row for prefix, cp in WORKLOADS.items() for ds in DATASETS for row in rows_for(prefix, cp, ds, a.sig)]
    path = ROOT / "results/n1_policy_only.csv"
    with open(path, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(out[0]))
        wr.writeheader()
        wr.writerows(out)
    print(f"{'workload':8} {'dataset':8} {'w':>4} {'scan/sel':>8} {'clock/scan':>10} {'bkt/scan':>8} "
          f"{'bkt+bind/scan':>13} {'e2e bkt':>7} {'e2e clk':>7} {'bkt err':>7}")
    for r in out:
        print(f"{r['workload']:8} {r['dataset']:8} {r['bucket_s']:>4} {r['scan_over_selector']:>8.2f} "
              f"{r['clock_over_scan']:>10.4f} {r['bucket_over_scan']:>8.3f} {r['bucket_bound_over_scan']:>13.3f} "
              f"{r['e2e_bucket_over_scan']:>7.3f} {r['e2e_clock_over_scan']:>7.4f} {100 * r['bucket_err_any']:>6.1f}%")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
