"""N5 A/B: conditional guessing bound and optimal finite-pool disclosure.

A computes the *ideal binary-transcript* bound. Transferring it to an
efficient adversary's real protocol view requires an adaptive simulation
argument and an enforcing wallet; this module does not establish either.
B solves an exact finite decision-tree problem, not all expressible policies.
See code/N5_DISCLOSURE.md for assumptions and mathematical attribution.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from numbers import Integral
from typing import Optional, Sequence

import numpy as np


def _natural(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return int(value)


def normalise_prior(prior: Optional[Sequence[float]], candidates: int) -> np.ndarray:
    """Accept probabilities or finite non-negative weights; retain zero mass."""
    if candidates < 1:
        raise ValueError("at least one candidate is required")
    if prior is None:
        return np.full(candidates, 1.0 / candidates)
    p = np.asarray(prior, dtype=float)
    if p.shape != (candidates,) or not np.isfinite(p).all() or (p < 0).any():
        raise ValueError("prior must contain one finite non-negative weight per candidate")
    if p.max() == 0:
        raise ValueError("prior must have positive total mass")
    p = p / p.max()  # avoid overflow when normalising large weights
    return p / p.sum()


def guessing_bound(prior_guess: float, budget: int) -> float:
    """min(1, 2**B * p0), averaged over transcripts, not a pointwise bound.

    p0 = E_S[max_t Pr(T=t | S)] for fixed classical side information.
    B counts *all* secret-dependent binary answers in the selected scope.
    No cryptographic error is estimated here. A real-view theorem for an
    efficient adversary would add its separately established simulation error.
    """
    b = _natural(budget, "budget")
    if not math.isfinite(prior_guess) or not 0 < prior_guess <= 1:
        raise ValueError("prior_guess must be in (0, 1]")
    if b >= -math.log2(prior_guess):
        return 1.0
    return min(1.0, math.ldexp(prior_guess, b))


class SearchLimitExceeded(RuntimeError):
    """Exact search exceeded its resource guard; no optimum is returned."""


@dataclass(frozen=True)
class DecisionNode:
    candidates: tuple[int, ...]
    query: Optional[int] = None
    no: Optional[DecisionNode] = None
    yes: Optional[DecisionNode] = None

    def to_dict(self) -> dict:
        out = {"candidates": list(self.candidates), "query": self.query}
        if self.query is not None:
            out.update(no=self.no.to_dict(), yes=self.yes.to_dict())
        return out


@dataclass(frozen=True)
class OptimalDisclosure:
    objective: str
    budget: int
    prior_guess: float
    posterior_guess: float
    leaves: int
    equivalence_classes: int
    equivalence_guess_ceiling: float
    states: int
    tree: DecisionNode

    @property
    def min_entropy_leakage_bits(self) -> float:
        return math.log2(self.posterior_guess / self.prior_guess)


def optimal_disclosure(answer_matrix: np.ndarray, budget: int,
                       prior: Optional[Sequence[float]] = None,
                       objective: str = "guessing", max_states: int = 200_000) -> OptimalDisclosure:
    """Optimal adaptive tree for a fixed Boolean (queries x candidates) matrix.

    Terminal reward is max ORIGINAL prior mass in the leaf for 'guessing',
    or one for 'leaves' (the capacity F). Branch rewards add. With a uniform
    prior, both objectives yield guessing success F/M. With a nonuniform
    prior, maximizing leaves need not maximize guessing success.

    Every answer costs one unit. Queries remain available at every node;
    repeats/constant queries cannot improve either objective and are skipped.
    No target-dependent refusal, time channel, or new side information is
    modelled. Exact search is exponential; exceeding max_states raises.
    """
    b = _natural(budget, "budget")
    limit = _natural(max_states, "max_states")
    if not limit:
        raise ValueError("max_states must be positive")
    if objective not in ("guessing", "leaves"):
        raise ValueError("objective must be 'guessing' or 'leaves'")
    raw = np.asarray(answer_matrix)
    if raw.ndim != 2 or raw.shape[1] == 0 or not np.isin(raw, [0, 1]).all():
        raise ValueError("answer_matrix must be Boolean with at least one candidate")
    A = raw.astype(bool)
    m = A.shape[1]
    p = normalise_prior(prior, m)
    classes = {}
    for i in range(m):
        classes.setdefault(A[:, i].tobytes(), []).append(i)
    ceiling = math.fsum(float(p[idx].max()) for idx in classes.values())
    choices = {}
    states = 0

    @lru_cache(maxsize=None)
    def solve(ids: tuple[int, ...], depth: int) -> tuple[float, int]:
        nonlocal states
        states += 1
        if states > limit:
            raise SearchLimitExceeded(f"exact search exceeded {limit} states")
        # (guessing success, leaf count); stopping is always allowed.
        best = (float(p[list(ids)].max()), 1)
        choices[(ids, depth)] = None
        if depth == 0 or len(ids) == 1:
            return best
        seen = set()
        for q, row in enumerate(A):
            yes = tuple(i for i in ids if row[i])
            if not yes or len(yes) == len(ids):
                continue
            no = tuple(i for i in ids if not row[i])
            split = tuple(sorted((no, yes)))
            if split in seen:  # duplicate/complement policies induce the same partition
                continue
            seen.add(split)
            left, right = solve(no, depth - 1), solve(yes, depth - 1)
            candidate = (left[0] + right[0], left[1] + right[1])
            key = lambda v: v if objective == "guessing" else (v[1], v[0])
            if key(candidate) > key(best):
                best = candidate
                choices[(ids, depth)] = (q, no, yes)
        return best

    # At most m-1 informative splits along a path, at most Q distinct queries.
    depth = min(b, m - 1, A.shape[0])
    root = tuple(range(m))
    score, leaves = solve(root, depth)

    def build(ids, d):
        choice = choices[(ids, d)]
        if choice is None:
            return DecisionNode(ids)
        q, no, yes = choice
        return DecisionNode(ids, q, build(no, d - 1), build(yes, d - 1))

    return OptimalDisclosure(objective, b, float(p.max()), min(1.0, score), leaves,
                             len(classes), min(1.0, ceiling), states, build(root, depth))
