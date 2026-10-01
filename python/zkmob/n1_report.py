"""Summarise the `n1_real` CSVs (claim N1 on real traces).

Per dataset and bucket width w: B3 error rate with 95% Wilson intervals,
split into false negatives (policy holds, B3 rejects: an honest user cannot
prove a true statement) and false positives (policy fails, B3 accepts: an
unsound statement gets proven), plus the median constraint ratio B3 / ours.

Two B3 discretisations are reported (see rust `automaton.rs`):
``carry`` (last fix carried forward; what the B3 circuit computes) and
``any`` (bucket flagged if any fix in it hits the zone; most favourable to B3).

Per item we also find w*, the coarsest width at which B3 is correct at w*
and at every finer width tried, and report B3's cost at w* versus ours.

    PYTHONPATH=python python3 -m zkmob.n1_report results/n1_real_*.csv
"""

from __future__ import annotations

import csv
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load(paths: List[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for p in paths:
        with open(p, newline="") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


VARIANTS = {"carry": "b3_answer", "any": "b3_any_answer"}


def summarise(rows: List[Dict[str, str]], variant: str) -> Tuple[List[Dict], List[Dict]]:
    col = VARIANTS[variant]
    by = defaultdict(list)
    for r in rows:
        by[(r["dataset"], int(r["bucket_s"]))].append(r)
    table = []
    for (ds, w), rs in sorted(by.items(), key=lambda kv: (kv[0][0], -kv[0][1])):
        pos = [r for r in rs if r["truth"] == "true"]
        neg = [r for r in rs if r["truth"] == "false"]
        fn = sum(r[col] == "false" for r in pos)
        fp = sum(r[col] == "true" for r in neg)
        err = fn + fp
        ratio = [int(r["b3_constraints"]) / int(r["ours_constraints"]) for r in rs]
        lo, hi = wilson(err, len(rs))
        table.append({
            "variant": variant, "dataset": ds, "bucket_s": w, "items": len(rs), "holds": len(pos),
            "b3_error": round(err / len(rs), 4), "b3_error_lo": round(lo, 4), "b3_error_hi": round(hi, 4),
            "b3_fn_rate": round(fn / len(pos), 4) if pos else "", "b3_fp_rate": round(fp / len(neg), 4) if neg else "",
            "ours_constraints_median": st.median(int(r["ours_constraints"]) for r in rs),
            "b3_constraints_median": st.median(int(r["b3_constraints"]) for r in rs),
            "b3_over_ours_median": round(st.median(ratio), 3),
            "b3_cheaper_share": round(sum(x < 1 for x in ratio) / len(ratio), 4),
        })

    # w*: coarsest width that is correct at itself and every finer width
    items = defaultdict(list)
    for r in rows:
        items[(r["dataset"], r["id"])].append(r)
    wstar = []
    for (ds, iid), rs in items.items():
        rs.sort(key=lambda r: int(r["bucket_s"]))           # finest first
        best = None
        for r in rs:
            if r[col] == r["truth"]:
                best = r
            else:
                break
        wstar.append({"variant": variant, "dataset": ds, "id": iid, "kind": rs[0]["kind"],
                      "w_star": int(best["bucket_s"]) if best else 0,
                      "ratio_at_w_star": int(best["b3_constraints"]) / int(best["ours_constraints"]) if best else float("nan")})
    return table, wstar


def main(paths: List[str]) -> None:
    rows = load(paths)
    table, wstar = [], []
    for variant in VARIANTS:
        t, w = summarise(rows, variant)
        table += t
        wstar += w
    pct = lambda v: "-" if v == "" else f"{v:.1%}"  # noqa: E731
    for variant in VARIANTS:
        print(f"\n=== B3 discretisation: {variant} ===")
        print(f"{'dataset':8} {'w(s)':>5} {'items':>6} {'B3 error [95% CI]':>22} {'FN':>6} {'FP':>6} {'B3/ours':>8} {'B3 cheaper':>10}")
        for t in (t for t in table if t["variant"] == variant):
            print(f"{t['dataset']:8} {t['bucket_s']:>5} {t['items']:>6} "
                  f"{t['b3_error']:>7.1%} [{t['b3_error_lo']:.1%},{t['b3_error_hi']:.1%}] "
                  f"{pct(t['b3_fn_rate']):>6} {pct(t['b3_fp_rate']):>6} "
                  f"{t['b3_over_ours_median']:>8.2f} {t['b3_cheaper_share']:>10.1%}")
        for ds in sorted({x["dataset"] for x in wstar}):
            xs = [x for x in wstar if x["dataset"] == ds and x["variant"] == variant]
            ok = [x for x in xs if x["w_star"] > 0]
            never = len(xs) - len(ok)
            if ok:
                print(f"  {ds}: median w* = {st.median(x['w_star'] for x in ok)} s; wrong even at 5 s on "
                      f"{never}/{len(xs)}; median B3/ours cost at w* = {st.median(x['ratio_at_w_star'] for x in ok):.2f}")
    for name, data in (("results/n1_real_summary.csv", table), ("results/n1_real_wstar.csv", wstar)):
        with open(name, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
    print("\nwrote results/n1_real_summary.csv and results/n1_real_wstar.csv")


if __name__ == "__main__":
    main(sys.argv[1:] or sorted(str(p) for p in Path("results").glob("n1_real_*.csv")
                                if "summary" not in p.name and "wstar" not in p.name))
