"""Baseline B5 / claim N5: what do repeated Boolean policy outcomes reveal?

Setting: the verifier (adversary) knows a prior set of M candidate routes
(e.g. plausible routes for this user) and may ask Boolean policy queries,
each answered by an honest ZK proof (1 bit). It keeps the candidates that
agree with every answer. We measure how fast the candidate set shrinks.

There is no model to train. Two quantities bracket the true leakage:
* an UPPER bound that holds for every attacker (`transcript_bound_bits`:
  B bits if every answer is charged, log2 sum_{i<=B} C(Q,i) if only "yes" is);
* a LOWER bound given by the strongest attacker we can run. The attackers
  below are therefore made as strong as practical, not tuned to a result.

Attackers:
* random   – queries drawn at random from a pool (weak, non-adaptive)
* adaptive – greedy: the pool query that best halves the remaining candidates
             (about one bit per answer; not provably optimal)
* cheap    – for charge="yes_only": the most information per expected charged
             slot, i.e. it seeks likely-"no" questions, which are free

Functions: `simulate` / `simulate_budget` (sampled targets),
`exact_partition` + `leakage_from_partition` (every target, no sampling),
`leakage_from_remaining` (Shannon, min-entropy, effective anonymity set).
Query pools can be uniform or weighted by historical visit counts.

Queries are cell-aligned so evaluation is vectorised with numpy; the test
suite cross-checks the vectorised answers against `policy.evaluate` and the
exact enumeration against the simulation.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

import numpy as np

from .policy import Box, Ordered, Policy, Step, Visit
from .trajectory import Point, random_grid_walk


@dataclass
class World:
    grid: int = 20          # cells per side
    cell_m: int = 250       # metres per cell  -> 5 km x 5 km
    steps: int = 60         # points per route
    step_s: int = 60        # seconds between points -> 1 hour
    n_candidates: int = 2000


@dataclass(frozen=True)
class Query:
    kind: str               # "visit" or "ordered"
    a: tuple                # (cx, cy) lower corner of zone A in cells
    b: tuple | None         # zone B for "ordered"
    side: int               # zone side in cells
    gap_steps: int | None   # ordered: B within gap_steps samples after A

    def to_policy(self, w: World) -> Policy:
        def box(c):
            return Box(c[0] * w.cell_m, (c[0] + self.side) * w.cell_m - 1,
                       c[1] * w.cell_m, (c[1] + self.side) * w.cell_m - 1)
        if self.kind == "visit":
            return Policy([Visit(box(self.a))])
        gap = self.gap_steps * w.step_s
        return Policy([Ordered([Step(box(self.a)), Step(box(self.b), gap)])])


def make_candidates(w: World, seed: int) -> np.ndarray:
    """Array (M, L, 2) of cell coordinates."""
    rng = random.Random(seed)
    out = np.zeros((w.n_candidates, w.steps, 2), dtype=np.int32)
    for m in range(w.n_candidates):
        tr = random_grid_walk(w.grid, w.cell_m, w.steps, w.step_s, rng)
        out[m, :, 0] = [p.x // w.cell_m for p in tr]
        out[m, :, 1] = [p.y // w.cell_m for p in tr]
    return out


def to_points(cells: np.ndarray, w: World) -> List[Point]:
    return [Point(int(c[0]) * w.cell_m + w.cell_m // 2, int(c[1]) * w.cell_m + w.cell_m // 2, i * w.step_s)
            for i, c in enumerate(cells)]


def make_pool(w: World, side: int, n: int, seed: int, weights: np.ndarray | None = None,
              gap_steps: Sequence[int] = (5, 10, 20, 40)) -> List[Query]:
    """Random query pool. Zone corners are uniform over the grid, or drawn
    in proportion to `weights` (grid x grid, e.g. historical visit counts:
    a verifier asks about places people actually go)."""
    rng = random.Random(seed)
    m = w.grid - side + 1
    if weights is not None:
        # weight of a corner = total weight of the side x side zone it spans
        c = np.pad(np.cumsum(np.cumsum(weights, 0), 1), ((1, 0), (1, 0)))
        zw = (c[side:, side:] - c[:-side, side:] - c[side:, :-side] + c[:-side, :-side])[:m, :m].ravel()
        corners = [(i // m, i % m) for i in range(m * m)]
        draw = lambda: corners[rng.choices(range(m * m), weights=zw)[0]]  # noqa: E731
    else:
        draw = lambda: (rng.randrange(m), rng.randrange(m))  # noqa: E731
    pool = []
    for _ in range(n):
        a = draw()
        if rng.random() < 0.5:
            pool.append(Query("visit", a, None, side, None))
        else:
            pool.append(Query("ordered", a, draw(), side, rng.choice(list(gap_steps))))
    return pool


def _inside(cands: np.ndarray, corner: tuple, side: int) -> np.ndarray:
    x, y = cands[..., 0], cands[..., 1]
    return (x >= corner[0]) & (x < corner[0] + side) & (y >= corner[1]) & (y < corner[1] + side)


def answers(cands: np.ndarray, q: Query) -> np.ndarray:
    """Vectorised outcome of query q on every candidate -> bool (M,)."""
    ina = _inside(cands, q.a, q.side)
    if q.kind == "visit":
        return ina.any(axis=1)
    inb = _inside(cands, q.b, q.side)
    # exists i < j with ina[i], inb[j], j - i <= gap  (fixed sampling period)
    g = q.gap_steps
    c = np.concatenate([np.zeros((cands.shape[0], 1), dtype=np.int32), np.cumsum(ina, axis=1, dtype=np.int32)], axis=1)
    L = cands.shape[1]
    j = np.arange(L)
    lo = np.maximum(j - g, 0)
    count_a = c[:, j] - c[:, lo]          # A's in [j-g, j-1]
    return ((count_a > 0) & inb).any(axis=1)


def run(w: World, side: int, attacker: str, max_q: int, trials: int, pool_size: int, seed: int) -> np.ndarray:
    """Remaining-candidate counts on synthetic routes, shape (trials, max_q + 1)."""
    cands = make_candidates(w, seed)
    pool = make_pool(w, side, pool_size, seed + 1)
    return simulate(cands, pool, attacker, max_q, trials, seed + 2)


def simulate(cands: np.ndarray, pool: Sequence[Query], attacker: str, max_q: int, trials: int,
             seed: int) -> np.ndarray:
    """Remaining-candidate counts for any candidate array (M, L, 2) of cell
    coordinates (cells outside the grid, e.g. padding, match no zone)."""
    A = np.stack([answers(cands, q) for q in pool])          # (Q, M)
    M = cands.shape[0]
    rng = np.random.default_rng(seed)
    res = np.zeros((trials, max_q + 1), dtype=np.int64)
    for tr in range(trials):
        truth = int(rng.integers(M))
        alive = np.ones(M, dtype=bool)
        used = np.zeros(len(pool), dtype=bool)
        res[tr, 0] = alive.sum()
        order = rng.permutation(len(pool))
        for k in range(1, max_q + 1):
            if attacker == "random":
                qi = int(order[k - 1])
            else:
                yes = (A[:, alive]).sum(axis=1)
                split = np.minimum(yes, alive.sum() - yes).astype(float)
                split[used] = -1
                qi = int(np.argmax(split))
            used[qi] = True
            alive &= A[qi] == A[qi, truth]
            res[tr, k] = alive.sum()
    return res


def main(out: str = "results/b5_leakage.csv", seed: int = 1) -> None:
    w = World()
    max_q, trials, pool = 40, 25, 600
    rows = []
    for side in (1, 2, 4):
        for attacker in ("random", "adaptive"):
            r = run(w, side, attacker, max_q, trials, pool, seed)
            for k in range(max_q + 1):
                col = r[:, k]
                rows.append({
                    "attacker": attacker, "zone_side_m": side * w.cell_m, "queries": k,
                    "median_remaining": float(np.median(col)), "p10_remaining": float(np.percentile(col, 10)),
                    "p90_remaining": float(np.percentile(col, 90)),
                    "share_identified": float(np.mean(col == 1)),
                })
            print(f"side={side * w.cell_m:>4} m {attacker:>8}: median remaining after 10/20/40 queries = "
                  f"{np.median(r[:, 10]):.0f} / {np.median(r[:, 20]):.0f} / {np.median(r[:, 40]):.0f}; "
                  f"identified after 40: {np.mean(r[:, 40] == 1):.0%}")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()


def simulate_budget(cands: np.ndarray, pool: Sequence[Query], attacker: str, budgets: Sequence[int], trials: int,
                    seed: int, charge: str = "all", max_total: int = 300) -> np.ndarray:
    """Remaining candidates when a per-trace budget B is exhausted.

    charge = "all"      every answer (yes or no) consumes one slot; needs
                        proofs of both outcomes (rust `budget.rs` scan circuit)
    charge = "yes_only" only "holds" answers produce a proof and consume a
                        slot; a "no" (no proof) is free, and after B yes
                        answers every reply is a refusal (no information)

    attacker = "adaptive" greedy halving; "cheap" maximises information per
    expected slot, H(p) / p for charge="yes_only" (it seeks likely-"no"
    queries), identical to "adaptive" for charge="all".
    Returns shape (trials, len(budgets)).
    """
    A = np.stack([answers(cands, q) for q in pool])          # (Q, M)
    M = cands.shape[0]
    rng = np.random.default_rng(seed)
    bmax = max(budgets)
    out = np.zeros((trials, len(budgets)), dtype=np.int64)
    for tr in range(trials):
        truth = int(rng.integers(M))
        alive = np.ones(M, dtype=bool)
        used = np.zeros(len(pool), dtype=bool)
        spent, total = 0, 0
        at_spent = {0: M}                                  # slots spent -> remaining
        while spent < bmax and total < max_total:
            n_alive = alive.sum()
            yes = A[:, alive].sum(axis=1).astype(float)
            p = yes / n_alive
            if attacker == "cheap" and charge == "yes_only":
                with np.errstate(divide="ignore", invalid="ignore"):
                    ent = -(np.where(p > 0, p * np.log2(p), 0) + np.where(p < 1, (1 - p) * np.log2(1 - p), 0))
                    score = np.where(p > 0, ent / np.maximum(p, 1e-9), 0.0)
            else:
                score = np.minimum(yes, n_alive - yes)
            score[used] = -1
            qi = int(np.argmax(score))
            if score[qi] <= 0:                              # nothing left to learn
                break
            used[qi] = True
            total += 1
            ans = A[qi, truth]
            alive &= A[qi] == ans
            if charge == "all" or ans:
                spent += 1
                at_spent[spent] = int(alive.sum())
        final = int(alive.sum())
        for bi, b in enumerate(budgets):
            # state when the b-th slot was spent; if never reached, the final state
            out[tr, bi] = at_spent.get(b, final) if b <= spent else final
    return out


# --------------------------------------------------------------------------
# Leakage metrics and bounds (N5 formal model)
# --------------------------------------------------------------------------

def transcript_bound_bits(budget: int, max_queries: int, charge: str) -> float:
    """Upper bound on leakage (Shannon or min-entropy, any prior) from the
    number of distinct transcripts a deterministic adaptive verifier can see.

    charge="all":      every answer costs a slot -> at most 2^B transcripts
                       -> L <= B (independent of how many queries are asked).
    charge="yes_only": only "yes" costs a slot; after Q queries the transcript
                       is a length-Q bit string with at most B ones
                       -> L <= log2 sum_{i<=B} C(Q, i)  (grows with Q).
    """
    import math
    if charge == "all":
        return float(min(budget, max_queries))
    b = min(budget, max_queries)
    return math.log2(sum(math.comb(max_queries, i) for i in range(b + 1)))


def leakage_from_remaining(remaining: np.ndarray, m: int) -> dict:
    """Leakage estimates when the prior is uniform over M candidates and the
    answers are deterministic (the posterior is uniform over the consistent
    candidates). `remaining` holds one consistent-set size per trial, with the
    target drawn uniformly, so trial averages estimate expectations.

    shannon_bits  = E[log2(M / A)]            = I(T; V)         (Shannon leakage)
    minent_bits   = log2(M * E[1 / A])        (min-entropy leakage, Smith 2009)
    A_eff         = 2^{H(T | V)} = 2^{E[log2 A]}  (effective anonymity set)
    """
    r = np.maximum(np.asarray(remaining, dtype=float), 1.0)
    bits = np.log2(m / r)
    n = len(bits)
    se = bits.std(ddof=1) / np.sqrt(n) if n > 1 else 0.0
    return {
        "shannon_bits": float(bits.mean()),
        "shannon_ci95": float(1.96 * se),
        "minent_bits": float(np.log2(m * np.mean(1.0 / r))),
        "a_eff": float(2 ** np.mean(np.log2(r))),
        "median_remaining": float(np.median(r)),
        "share_identified": float(np.mean(r == 1)),
    }


def _choose(A_alive: np.ndarray, n_alive: int, used: np.ndarray, attacker: str, charge: str) -> int:
    """Same query rule as `simulate_budget` (greedy halving, or bits per
    expected slot for the 'cheap' attacker under charge='yes_only').
    Returns -1 when no query splits the alive set."""
    yes = A_alive.sum(axis=1).astype(float)
    if attacker == "cheap" and charge == "yes_only":
        p = yes / n_alive
        with np.errstate(divide="ignore", invalid="ignore"):
            ent = -(np.where(p > 0, p * np.log2(p), 0) + np.where(p < 1, (1 - p) * np.log2(1 - p), 0))
            score = np.where(p > 0, ent / np.maximum(p, 1e-9), 0.0)
    else:
        score = np.minimum(yes, n_alive - yes)
    score[used] = -1
    q = int(np.argmax(score))
    return q if score[q] > 0 else -1


def exact_partition(A: np.ndarray, attacker: str, budget: int, charge: str, max_total: int) -> List[int]:
    """Enumerate the verifier's whole decision tree for EVERY possible target
    (no sampling). A is the (queries x candidates) answer matrix. Returns the
    sizes of the final candidate classes (the leaves): the target is known to
    lie in its class and nothing more. Each internal node splits its set into
    two non-empty parts, so the tree has at most 2M - 1 nodes.

    Exact evaluation of the chosen GREEDY strategy, not optimisation over
    all strategies. See disclosure.optimal_disclosure for the latter.
    """
    M = A.shape[1]
    leaves: List[int] = []
    stack = [(np.arange(M), np.zeros(A.shape[0], dtype=bool), 0, 0)]   # (alive idx, used, spent, depth)
    while stack:
        idx, used, spent, depth = stack.pop()
        if spent >= budget or depth >= max_total or len(idx) == 1:
            leaves.append(len(idx))
            continue
        q = _choose(A[:, idx], len(idx), used, attacker, charge)
        if q < 0:
            leaves.append(len(idx))
            continue
        used2 = used.copy()
        used2[q] = True
        ans = A[q, idx]
        for branch, sub in ((True, idx[ans]), (False, idx[~ans])):
            cost = 1 if (charge == "all" or branch) else 0
            stack.append((sub, used2, spent + cost, depth + 1))
    return leaves


def leakage_from_partition(leaves: Sequence[int]) -> dict:
    """Exact leakage for a uniform prior and a deterministic strategy whose
    final classes have the given sizes (Sum = M)."""
    s = np.asarray(leaves, dtype=float)
    M = s.sum()
    w = s / M
    return {
        "shannon_bits": float(np.sum(w * np.log2(M / s))),
        "shannon_ci95": 0.0,
        "minent_bits": float(np.log2(len(s))),
        "a_eff": float(2 ** np.sum(w * np.log2(s))),
        "median_remaining": float(np.repeat(s, s.astype(int))[int(M) // 2]) if M < 5e6 else float("nan"),
        "share_identified": float(np.sum(s == 1) / M),
    }
