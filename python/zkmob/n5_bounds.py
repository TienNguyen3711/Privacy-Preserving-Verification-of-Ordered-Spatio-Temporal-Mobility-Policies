"""N5 formal model, checked on real data.

Experiment A — leakage versus the charging rule (one trip). EXACT: the
  verifier's decision tree is enumerated for every possible target, so the
  Shannon and min-entropy leakage below are exact for a uniform prior.
  A deterministic adaptive verifier sees at most 2^B transcripts when every
  answer costs a slot, but up to sum_{i<=B} C(Q, i) when only "yes" answers
  cost a slot and Q queries are asked. Hence (Lemma, any prior)
      charge=all       L <= B
      charge=yes_only  L <= log2 sum_{i<=B} C(Q, i)   (grows with Q)
  We sweep Q and B and compare measured Shannon and min-entropy leakage with
  both bounds.

Experiment B — cumulative leakage about a person over K traces.
  The secret is the user (taxi / GeoLife user) U. The verifier gets B answers
  on each of K DIFFERENT trips of the same user (budget per trace); the K
  trips are a uniform draw without replacement from that user's
  evaluation-period trips. The posterior over users is exact for this
  sampler: the likelihood of user u is the number of ways to assign the K
  traces to distinct trips of u consistent with their answers, divided by the
  number of ordered K-tuples of distinct trips of u (`distinct_assignments`).
  (Before 1 Oct 2026 the likelihood assumed independent draws with
  replacement, which does not match this sampler; review R6.) Queries are
  chosen greedily; only the posterior used for reporting must be exact.
  By the chain rule
      I(U; answers) <= K * B,
  so per-trace budgets do NOT bound per-user leakage; K traces multiply it.
  The posterior is non-uniform, so the effective anonymity set 2^{H(U|V)}
  and the min-entropy leakage differ from a candidate count.
  With --device (review RR-11, 3 Oct 2026) the budget is per device: B answers
  in total, spread as evenly as possible over the K trips, so
      I(U; answers) <= B   whatever K.

    PYTHONPATH=python python3 -m zkmob.n5_bounds
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence

import numpy as np

from .datasets import Trip, geolife_files, load_geolife, load_porto, time_split
from .leakage import World, answers, exact_partition, leakage_from_partition, make_pool, transcript_bound_bits
from .n5_real import BEIJING_WIN, PORTO_WIN, Window, dedupe, popularity, to_cells

Q_SWEEP = (20, 50, 100, 300)
B_SWEEP = (1, 2, 3, 4, 6, 8)
K_SWEEP = (1, 2, 4, 8)
B_USER = (1, 2, 4)
B_DEVICE = (4, 8)


def _setup(trips: Sequence[Trip], win: Window, period: int, length: int, seed: int, pool_size: int):
    hist, evalp = time_split(trips)
    h_cells, _ = to_cells(hist, win, period, length)
    e_cells, e_kept = to_cells(evalp, win, period, length)
    w = World(grid=win.grid, cell_m=win.cell_m, steps=length, step_s=period, n_candidates=len(e_cells))
    gaps = tuple(max(1, g // period) for g in (300, 600, 1200, 2400))
    pool = make_pool(w, 1, pool_size, seed + 1, popularity(h_cells, win.grid), gaps)
    return e_cells, e_kept, pool


# --------------------------------------------------------------------------
# Experiment A
# --------------------------------------------------------------------------

def experiment_a(name, e_cells, pool, seed) -> List[Dict]:
    """Exact (enumerates the verifier's decision tree for every target)."""
    cands = dedupe(e_cells)
    if len(cands) > 2000:
        cands = cands[np.sort(np.random.default_rng(seed).choice(len(cands), 2000, replace=False))]
    M = len(cands)
    A = np.stack([answers(cands, q) for q in pool])          # (Q, M)
    rows = []
    runs = [("all", "adaptive", max(Q_SWEEP))]
    runs += [("yes_only", att, q) for att in ("adaptive", "cheap") for q in Q_SWEEP]
    for charge, attacker, q in runs:
        for b in B_SWEEP:
            met = leakage_from_partition(exact_partition(A, attacker, b, charge, q))
            bound = transcript_bound_bits(b, q, charge)
            rows.append({"scope": name, "candidates": M, "charge": charge, "attacker": attacker, "max_queries": q,
                         "budget": b, **met, "bound_bits": bound, "prior_bits": float(np.log2(M)),
                         "within_bound": met["shannon_bits"] <= bound + 1e-9 and met["minent_bits"] <= bound + 1e-9,
                         "method": "exact"})
        show = ", ".join(f"B={b}: {rows[-len(B_SWEEP) + i]['shannon_bits']:.1f}/{rows[-len(B_SWEEP) + i]['bound_bits']:.1f}"
                         for i, b in enumerate(B_SWEEP))
        print(f"  {name:>9} M={M:>4} {charge:>8} {attacker:>8} Q={q:>3}  Shannon/bound bits: {show}")
    return rows


# --------------------------------------------------------------------------
# Experiment B
# --------------------------------------------------------------------------

def distinct_assignments(member: np.ndarray, owner: np.ndarray, n_users: int) -> np.ndarray:
    """Per user, the number of injective maps from traces to that user's trips
    with trace k mapped into its consistent set.

    member: (K, N) bool, member[k, t] = trip t is consistent with trace k's
    answers. owner: (N,) user index of each trip. Returns (n_users,) float64.
    Dynamic programming over subsets of traces, vectorised over users: trips
    are processed in rounds (the r-th trip of every user at once).
    """
    K, N = member.shape
    masks = np.zeros(N, dtype=np.int64)
    for k in range(K):
        masks |= member[k].astype(np.int64) << k
    order = np.argsort(owner, kind="stable")
    rank = np.empty(N, dtype=np.int64)
    counts = np.bincount(owner, minlength=n_users)
    starts = np.concatenate([[0], np.cumsum(counts)[:-1]])
    rank[order] = np.arange(N) - np.repeat(starts, counts)
    dp = np.zeros((n_users, 1 << K))
    dp[:, 0] = 1.0
    full = np.arange(1 << K)
    for r in range(int(counts.max(initial=0))):
        trips = np.flatnonzero(rank == r)
        users, m = owner[trips], masks[trips]
        new = dp.copy()
        for k in range(K):
            sel = users[(m >> k) & 1 == 1]
            if len(sel) == 0:
                continue
            free = full[(full >> k) & 1 == 0]
            new[np.ix_(sel, free | (1 << k))] += dp[np.ix_(sel, free)]
        dp = new
    return dp[:, (1 << K) - 1]


def falling(n: np.ndarray, k: int) -> np.ndarray:
    out = np.ones_like(n, dtype=np.float64)
    for i in range(k):
        out *= np.maximum(n - i, 0)
    return out

def experiment_b(name, e_cells, e_kept, pool, trials, seed, min_trips=10, max_trips=30, device=False) -> List[Dict]:
    rng = np.random.default_rng(seed)
    by_user: Dict[str, List[int]] = defaultdict(list)
    for i, tr in enumerate(e_kept):
        by_user[tr.owner].append(i)
    users = sorted(u for u, idx in by_user.items() if len(idx) >= min_trips)
    if len(users) < 5:
        print(f"  {name}: skipped (only {len(users)} users with >= {min_trips} trips)")
        return []
    trip_ids, owner = [], []
    for ui, u in enumerate(users):
        idx = by_user[u]
        if len(idx) > max_trips:
            idx = list(rng.choice(idx, max_trips, replace=False))
        trip_ids += idx
        owner += [ui] * len(idx)
    cells = e_cells[trip_ids]
    owner = np.array(owner)
    U, N = len(users), len(owner)
    inc = np.zeros((N, U), dtype=np.float32)
    inc[np.arange(N), owner] = 1.0
    n_u = inc.sum(axis=0)                                   # trips per user
    A = np.stack([answers(cells, q) for q in pool])         # (Q, N)
    Af = A.astype(np.float32)
    prior_bits = float(np.log2(U))

    def entropy(p):
        p = p[p > 0]
        return float(-(p * np.log2(p)).sum())

    rows = []
    for B in (B_DEVICE if device else B_USER):
        for K in K_SWEEP:
            # answers per trip: B each (per-trace budget) or B in total (device budget)
            alloc = [B // K + (i < B % K) for i in range(K)] if device else [B] * K
            bound = B if device else K * B
            h_post, maxpost, hit = [], [], []
            for _ in range(trials):
                truth = int(rng.integers(U))
                mine = np.flatnonzero(owner == truth)
                assert len(mine) >= K, "min_trips must be at least K"
                picked = rng.choice(mine, K, replace=False)
                logpost = np.zeros(U)
                consistent = []
                for t, b_t in zip(picked, alloc):
                    alive = np.ones(N, dtype=bool)
                    used = np.zeros(len(pool), dtype=bool)
                    for _ in range(b_t):
                        alive_u = alive.astype(np.float32) @ inc                    # (U,)
                        base = np.exp(logpost - logpost.max()) * (alive_u / n_u)
                        post = base / base.sum()
                        yes_u = (Af[:, alive] @ inc[alive])                         # (Q, U)
                        with np.errstate(divide="ignore", invalid="ignore"):
                            # float64: 1e-300 underflows to 0 in float32 and makes every gain NaN
                            p = np.where(alive_u > 0, yes_u.astype(np.float64) / alive_u, 0.0)
                        pyes = p @ post
                        def hb(x):
                            x = np.clip(np.asarray(x, dtype=np.float64), 0.0, 1.0)
                            return -(x * np.log2(np.maximum(x, 1e-300)) + (1 - x) * np.log2(np.maximum(1 - x, 1e-300)))
                        gain = hb(pyes) - hb(p) @ post
                        assert not np.isnan(gain).any(), "NaN information gain"
                        gain[used] = -1
                        q = int(np.argmax(gain))
                        used[q] = True
                        alive &= A[q] == A[q, t]
                    consistent.append(alive.copy())
                    # exact posterior after this trace (without-replacement sampler)
                    like = distinct_assignments(np.array(consistent), owner, U) / falling(n_u, len(consistent))
                    with np.errstate(divide="ignore"):
                        logpost = np.log(like)
                post = np.exp(logpost - logpost.max())
                post /= post.sum()
                h_post.append(entropy(post))
                maxpost.append(float(post.max()))
                hit.append(int(np.argmax(post) == truth))
            h_post = np.array(h_post)
            shannon = prior_bits - h_post.mean()
            se = h_post.std(ddof=1) / np.sqrt(len(h_post))
            minent = float(np.log2(U * np.mean(maxpost)))
            rows.append({"scope": name, "users": U, "trips_used": N,
                         "budget_scope": "device" if device else "trace", "budget": B, "traces": K,
                         "shannon_bits": float(shannon), "shannon_ci95": float(1.96 * se), "minent_bits": minent,
                         "a_eff": float(2 ** h_post.mean()), "top1_identified": float(np.mean(hit)),
                         "bound_bits": float(bound), "prior_bits": prior_bits,
                         # Monte Carlo: the Shannon estimate is unbiased; the
                         # min-entropy estimate is noisy, so only Shannon is checked
                         "within_bound": shannon <= bound + 1e-9, "method": f"monte_carlo_{trials}"})
            print(f"  {name:>9} U={U:>3} {'device' if device else 'trace'} B={B} K={K}: Shannon {shannon:5.2f} (bound {bound:>2}), min-entropy {minent:5.2f}, "
                  f"A_eff {2 ** h_post.mean():6.1f} of {U}, top-1 identified {np.mean(hit):.0%}")
    return rows


def write(rows: List[Dict], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {path} ({len(rows)} rows)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--pool", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only-b", action="store_true", help="rerun Experiment B only")
    ap.add_argument("--device", action="store_true",
                    help="Experiment B with a per-device budget; writes results/n5_bounds_users_device.csv")
    ap.add_argument("--geolife-users-b", type=int, default=0,
                    help="GeoLife users loaded for Experiment B (top by file count; 0 = all 182). "
                         "Experiment A keeps the 40 users with the most files. Before 6 Oct 2026, B also "
                         "used those 40 users, which left 24 persons after filtering.")
    a = ap.parse_args()

    porto = load_porto(max_rows=60_000)
    p_cells, p_kept, p_pool = _setup(porto, PORTO_WIN, 15, 120, a.seed, a.pool)
    files = geolife_files()
    users = sorted(files, key=lambda u: -len(files[u]))[:40]
    geo = load_geolife(users=users)
    g_cells, g_kept, g_pool = _setup(geo, BEIJING_WIN, 30, 120, a.seed, a.pool)

    rows_a: List[Dict] = []
    if not a.only_b:
        print("Experiment A: leakage versus charging rule (Porto city, one trip)")
        rows_a = experiment_a("porto", p_cells, p_pool, a.seed)
        rows_a += experiment_a("geolife", g_cells, g_pool, a.seed)
        write(rows_a, "results/n5_bounds_charging.csv")

    print("Experiment B: leakage about the person over K traces")
    rows_b = experiment_b("porto", p_cells, p_kept, p_pool, a.trials, a.seed, device=a.device)
    users_b = sorted(files, key=lambda u: -len(files[u]))
    if a.geolife_users_b:
        users_b = users_b[:a.geolife_users_b]
    if users_b != users:
        geo_b = load_geolife(users=users_b)
        gb_cells, gb_kept, gb_pool = _setup(geo_b, BEIJING_WIN, 30, 120, a.seed, a.pool)
    else:
        gb_cells, gb_kept, gb_pool = g_cells, g_kept, g_pool
    rows_b += experiment_b("geolife", gb_cells, gb_kept, gb_pool, a.trials, a.seed, device=a.device)
    write(rows_b, "results/n5_bounds_users_device.csv" if a.device else "results/n5_bounds_users.csv")

    bad = [r for r in rows_a + rows_b if not r["within_bound"]]
    print(f"bound violations: {len(bad)} of {len(rows_a) + len(rows_b)} settings")


if __name__ == "__main__":
    main()
