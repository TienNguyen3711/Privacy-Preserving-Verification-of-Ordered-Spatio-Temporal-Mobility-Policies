"""C3 Experiment A with the trace length public (review R7, option b).

In the Groth16 instantiation the circuit fixes the trace length n, so a
verifier learns the target's length class before it asks anything. This
script reruns Experiment A of `n5_bounds` (same candidates, same query pool,
same greedy verifier, exact decision-tree enumeration) with the uniform prior
conditioned on a length class:

  none   no length information (the published setting; reproduces
         results/n5_bounds_charging.csv)
  pow2   n padded to the next power of two, at least 32 (one circuit per
         padded size, as a deployment would compile)
  exact  the recorded fix count n itself (one circuit per length; worst case)

For each scheme the verifier's tree is enumerated separately inside every
class. With a uniform prior over M candidates, the min-entropy leakage of
(class, transcript) is log2(#nonempty cells), and the leakage beyond the
length is that minus log2(#nonempty classes); charging every answer keeps the
latter at most B bits (Lemma 1 applied per class).

    PYTHONPATH=python python3 -m zkmob.n5_length_classes
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import numpy as np

from .datasets import geolife_files, load_geolife, load_porto
from .leakage import exact_partition, transcript_bound_bits
from .n5_bounds import B_SWEEP, _setup
from .n5_real import BEIJING_WIN, PORTO_WIN

Q = 100
UNBUDGETED = 20   # adaptive queries without a budget (identification check)


def length_class(n: int, scheme: str) -> int:
    if scheme == "none":
        return 0
    if scheme == "exact":
        return n
    return max(32, 1 << int(np.ceil(np.log2(max(n, 1)))))


def candidates(e_cells: np.ndarray, e_kept, seed: int):
    """Same candidate set as n5_bounds.experiment_a, with the fix count of
    each candidate (dedupe keeps the first trip of each cell sequence)."""
    _, idx = np.unique(e_cells.reshape(e_cells.shape[0], -1), axis=0, return_index=True)
    idx = np.sort(idx)
    cands, lens = e_cells[idx], np.array([len(e_kept[i]) for i in idx])
    if len(cands) > 2000:
        pick = np.sort(np.random.default_rng(seed).choice(len(cands), 2000, replace=False))
        cands, lens = cands[pick], lens[pick]
    return cands, lens


def run(name: str, cands: np.ndarray, lens: np.ndarray, A: np.ndarray) -> List[Dict]:
    M = A.shape[1]
    rows = []
    for scheme in ("none", "pow2", "exact"):
        cls = np.array([length_class(int(n), scheme) for n in lens])
        groups = defaultdict(list)
        for j, c in enumerate(cls):
            groups[c].append(j)
        groups = {c: np.array(v) for c, v in groups.items()}
        n_cls = len(groups)
        sizes = np.array([len(v) for v in groups.values()])
        alone = int(np.sum(sizes == 1))
        settings = [("all", b, Q) for b in B_SWEEP] + [("yes_only", b, Q) for b in B_SWEEP]
        settings += [("all", UNBUDGETED, UNBUDGETED)]
        for charge, b, q in settings:
            leaves: List[int] = []
            for v in groups.values():
                leaves += exact_partition(A[:, v], "adaptive", b, charge, q)
            s = np.asarray(leaves, dtype=float)
            cells = len(s)
            total = float(np.log2(cells))
            rows.append({
                "scope": name, "candidates": M, "length_scheme": scheme, "classes": n_cls,
                "classes_singleton": alone, "largest_class": int(sizes.max()),
                "length_bits": float(np.log2(n_cls)),
                "cond_prior_bits": float(np.log2(M / n_cls)),
                "charge": charge, "budget": b, "max_queries": q,
                "minent_total_bits": total,
                "minent_beyond_length_bits": total - float(np.log2(n_cls)),
                "bound_beyond_length_bits": transcript_bound_bits(b, q, charge),
                "share_identified": float(np.sum(s == 1) / M),
                "method": "exact",
            })
        r = [x for x in rows if x["length_scheme"] == scheme]
        def get(ch, b):
            return next(x for x in r if x["charge"] == ch and x["budget"] == b)
        print(f"  {name:>8} {scheme:>5}: classes={n_cls:>4} (singletons {alone}), length={np.log2(n_cls):.2f} b, "
              f"all B=4 total/beyond={get('all', 4)['minent_total_bits']:.2f}/{get('all', 4)['minent_beyond_length_bits']:.2f} b "
              f"id={get('all', 4)['share_identified']:.1%}; yes-only B=4 total={get('yes_only', 4)['minent_total_bits']:.2f} b "
              f"id={get('yes_only', 4)['share_identified']:.1%}; unbudgeted Q=20 id={get('all', UNBUDGETED)['share_identified']:.1%}")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="results/n5_length_classes.csv")
    a = ap.parse_args()
    from .leakage import answers

    porto = load_porto(max_rows=60_000)
    p_cells, p_kept, p_pool = _setup(porto, PORTO_WIN, 15, 120, a.seed, a.pool)
    files = geolife_files()
    users = sorted(files, key=lambda u: -len(files[u]))[:40]
    geo = load_geolife(users=users)
    g_cells, g_kept, g_pool = _setup(geo, BEIJING_WIN, 30, 120, a.seed, a.pool)

    rows: List[Dict] = []
    for name, cells, kept, pool in (("porto", p_cells, p_kept, p_pool), ("geolife", g_cells, g_kept, g_pool)):
        cands, lens = candidates(cells, kept, a.seed)
        A = np.stack([answers(cands, q) for q in pool])
        print(f"{name}: M={len(cands)}, fixes median {int(np.median(lens))} (p10 {int(np.percentile(lens, 10))}, "
              f"p90 {int(np.percentile(lens, 90))})")
        rows += run(name, cands, lens, A)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {a.out} ({len(rows)} rows)")
    bad = [r for r in rows if r["charge"] == "all" and r["budget"] in B_SWEEP
           and r["minent_beyond_length_bits"] > r["budget"] + 1e-9]
    print(f"beyond-length bound violations (charge all): {len(bad)}")


if __name__ == "__main__":
    main()
