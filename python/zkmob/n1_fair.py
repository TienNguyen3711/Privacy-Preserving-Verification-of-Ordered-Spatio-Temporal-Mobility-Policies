"""N1 on a like-for-like cost basis (review RR-01 to RR-05, 3 Oct 2026).

Reads the `n1_real` CSVs (16-bit coordinates, 17-bit time). Per dataset and
bucket width w it reports:

* B3 error rates for three discretisations: ``any`` (any fix in the bucket),
  ``carry`` (carry-forward, what the B3 circuit computes) and ``sound`` (the
  conservative window floor(gap/w)-1, which never accepts a false statement
  and so errs only by rejecting true ones);
* median cost ratios, B3 over ours, on three bases:
    - ``dfa/selector``: the pre-review basis (B3's DFA vs the selector, which
      proves only "holds");
    - ``bound/scan``: B3's DFA plus the lower bound on binding its buckets to
      the committed fixes, vs the scan circuit that proves either outcome;
    - ``e2e``: both plus the shared commitment and the signature layer
      (Lamport + Merkle, SIG constraints), i.e. the whole relation;
* error by policy kind (tight, loose, reversed): the workload anchors zones
  on the trace, so tight policies sit near the decision boundary (RR-04);
  results/n1_fair_by_factor.csv splits tight policies by Delta / anchor gap.

Writes results/n1_fair_summary.csv and prints a compact table. With
``--prefix n1_grid`` it reads the grid workload of `n1_grid_export` instead
and writes results/n1_grid_summary.csv (no by-factor split: gaps there are
not set relative to the trace).

    PYTHONPATH=python python3 -m zkmob.n1_fair [--sig 133931] [--prefix n1_grid]
"""

from __future__ import annotations

import argparse
import csv
import statistics as st
from collections import defaultdict
from pathlib import Path

from .n1_report import wilson

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ("geolife", "porto", "tdrive")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sig", type=int, default=133_931,
                    help="Lamport verification + 22 Merkle levels (constraints; from n4_link)")
    ap.add_argument("--prefix", default="n1_real", choices=["n1_real", "n1_grid"])
    a = ap.parse_args()
    out = []
    for ds in DATASETS:
        rows = list(csv.DictReader(open(ROOT / f"results/{a.prefix}_{ds}.csv")))
        by_w = defaultdict(list)
        for r in rows:
            by_w[int(r["bucket_s"])].append(r)
        for w in sorted(by_w, reverse=True):
            rs = by_w[w]
            truth = [r["truth"] == "true" for r in rs]
            def err(col):
                return sum((r[col] == "true") != t for r, t in zip(rs, truth))
            e_any, e_carry, e_sound = err("b3_any_answer"), err("b3_answer"), err("b3_sound_answer")
            fp_any = sum(r["b3_any_answer"] == "true" and not t for r, t in zip(rs, truth))
            fp_sound = sum(r["b3_sound_answer"] == "true" and not t for r, t in zip(rs, truth))
            assert fp_sound == 0
            n = len(rs)
            dfa = [int(r["b3_constraints"]) for r in rs]
            bind = [int(r["b3_binding_lb"]) for r in rs]
            sel = [int(r["ours_constraints"]) for r in rs]
            scan = [int(r["ours_scan"]) for r in rs]
            com = [int(r["commit"]) for r in rs]
            ratio = lambda num, den: st.median(x / y for x, y in zip(num, den))
            kinds = defaultdict(list)
            for r, t in zip(rs, truth):
                kinds[r["kind"]].append((r["b3_any_answer"] == "true") != t)
            lo, hi = wilson(e_any, n)
            out.append({
                "dataset": ds, "bucket_s": w, "items": n,
                "err_any": round(e_any / n, 4), "err_any_lo": round(lo, 4), "err_any_hi": round(hi, 4),
                "fp_any": round(fp_any / n, 4),
                "err_carry": round(e_carry / n, 4), "err_sound": round(e_sound / n, 4),
                "err_any_tight": round(sum(kinds["tight"]) / max(1, len(kinds["tight"])), 4),
                "err_any_loose": round(sum(kinds["loose"]) / max(1, len(kinds["loose"])), 4),
                "err_any_reversed": round(sum(kinds["reversed"]) / max(1, len(kinds["reversed"])), 4),
                "ratio_dfa_over_selector": round(ratio(dfa, sel), 3),
                "ratio_dfa_over_scan": round(ratio(dfa, scan), 3),
                "ratio_bound_over_scan": round(ratio([d + b for d, b in zip(dfa, bind)], scan), 3),
                "ratio_e2e": round(ratio([c + a.sig + d + b for c, d, b in zip(com, dfa, bind)],
                                         [c + a.sig + s for c, s in zip(com, scan)]), 3),
                "median_n": st.median(int(r["n_points"]) for r in rs),
                "median_scan": st.median(scan), "median_selector": st.median(sel), "median_commit": st.median(com),
            })
    by_factor = []
    for ds in DATASETS if a.prefix == "n1_real" else ():
        acc = defaultdict(lambda: [0, 0])
        for r in csv.DictReader(open(ROOT / f"results/n1_real_{ds}.csv")):
            key = (int(r["bucket_s"]), r["kind"], r["gap_factor"] or "-")
            acc[key][0] += (r["b3_any_answer"] == "true") != (r["truth"] == "true")
            acc[key][1] += 1
        for (w, kind, f), (e, n) in sorted(acc.items()):
            by_factor.append({"dataset": ds, "bucket_s": w, "kind": kind, "delta_over_gap": f,
                              "items": n, "err_any": round(e / n, 4)})
    if by_factor:
        with open(ROOT / "results/n1_fair_by_factor.csv", "w", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(by_factor[0]))
            wr.writeheader()
            wr.writerows(by_factor)
    path = ROOT / ("results/n1_fair_summary.csv" if a.prefix == "n1_real" else "results/n1_grid_summary.csv")
    with open(path, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(out[0]))
        wr.writeheader()
        wr.writerows(out)
    for r in out:
        print(f"{r['dataset']:8s} w={r['bucket_s']:>4} err any {100*r['err_any']:5.1f}% (fp {100*r['fp_any']:4.1f}) "
              f"carry {100*r['err_carry']:5.1f}% sound {100*r['err_sound']:5.1f}% | tight {100*r['err_any_tight']:5.1f}% "
              f"loose {100*r['err_any_loose']:4.1f}% rev {100*r['err_any_reversed']:4.1f}% | dfa/sel {r['ratio_dfa_over_selector']:8.2f} "
              f"dfa/scan {r['ratio_dfa_over_scan']:6.2f} bound/scan {r['ratio_bound_over_scan']:6.2f} e2e {r['ratio_e2e']:5.2f}")
    print("median n, scan, selector, commit:", {r["dataset"]: (r["median_n"], r["median_scan"], r["median_selector"], r["median_commit"]) for r in out if r["bucket_s"] == 60})
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
