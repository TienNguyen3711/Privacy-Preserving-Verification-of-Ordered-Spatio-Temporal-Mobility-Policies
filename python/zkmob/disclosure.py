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


def _indices(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


class DisclosureSolver:
    """Reusable exact bitset solver for one matrix, prior and objective.

    Globally indistinguishable candidates form atoms. Atom reward is the
    largest ORIGINAL prior mass in that atom. Floats are converted to exact
    integer ratios, so branch-and-bound never prunes using rounded scores.
    The admissible ceiling is the sum of the largest min(2**depth, atoms)
    atom rewards, with that many leaves as a secondary ceiling.

    Memoised states are reused across budgets. max_states caps cumulative
    newly expanded states for this solver instance; exhaustion raises, never
    returns an approximate optimum. Returned `states` counts new states for
    that call. Query indices and leaf candidate IDs refer to the input matrix.
    """

    def __init__(self, answer_matrix, prior=None, objective="guessing", max_states=200_000):
        self.limit = _natural(max_states, "max_states")
        if not self.limit:
            raise ValueError("max_states must be positive")
        if objective not in ("guessing", "leaves"):
            raise ValueError("objective must be 'guessing' or 'leaves'")
        raw = np.asarray(answer_matrix)
        if raw.ndim != 2 or raw.shape[1] == 0 or not np.isin(raw, [0, 1]).all():
            raise ValueError("answer_matrix must be Boolean with at least one candidate")
        A = raw.astype(bool)
        self.p = normalise_prior(prior, A.shape[1])
        self.objective = objective
        classes = {}
        for i in range(A.shape[1]):
            classes.setdefault(A[:, i].tobytes(), []).append(i)
        self.atoms = list(classes.values())
        ratios = [float(self.p[ids].max()).as_integer_ratio() for ids in self.atoms]
        self.denominator = max(den for _, den in ratios)  # IEEE float denominators are powers of two
        self.weights = [num * (self.denominator // den) for num, den in ratios]
        self.root = (1 << len(self.atoms)) - 1
        self.queries = []
        seen = set()
        for q, row in enumerate(A):
            mask = sum(1 << j for j, ids in enumerate(self.atoms) if row[ids[0]])
            split = min(mask, self.root ^ mask)
            if split and split not in seen:
                seen.add(split)
                self.queries.append((q, mask))
        self.cache, self.choices, self.weight_cache = {}, {}, {}
        self.total_states = 0

    def _key(self, score):
        return score if self.objective == "guessing" else (score[1], score[0])

    def _weights(self, mask):
        if mask not in self.weight_cache:
            self.weight_cache[mask] = sorted((self.weights[i] for i in _indices(mask)), reverse=True)
        return self.weight_cache[mask]

    def _upper(self, mask, depth):
        weights = self._weights(mask)
        k = min(1 << depth, len(weights))
        return sum(weights[:k]), k

    def _solve(self, mask, depth):
        state = (mask, depth)
        if state in self.cache:
            return self.cache[state]
        self.total_states += 1
        if self.total_states > self.limit:
            raise SearchLimitExceeded(f"exact search exceeded {self.limit} cumulative states")
        best = (self._weights(mask)[0], 1)
        choice = None
        if depth and mask & (mask - 1):
            upper = self._upper(mask, depth)
            seen, splits = set(), []
            for q, query in self.queries:
                yes = mask & query
                no = mask ^ yes
                split = min(yes, no)
                if not split or split in seen:
                    continue
                seen.add(split)
                l, r = self._upper(no, depth - 1), self._upper(yes, depth - 1)
                bound = (l[0] + r[0], l[1] + r[1])
                splits.append((bound, q, no, yes))
            # Visit promising branches first, deterministically retaining input order on ties.
            splits.sort(key=lambda x: self._key(x[0]), reverse=True)
            for bound, q, no, yes in splits:
                if self._key(best) >= self._key(upper):
                    break
                if self._key(bound) <= self._key(best):
                    continue
                left = self._solve(no, depth - 1)
                r = self._upper(yes, depth - 1)
                if self._key((left[0] + r[0], left[1] + r[1])) <= self._key(best):
                    continue
                right = self._solve(yes, depth - 1)
                candidate = (left[0] + right[0], left[1] + right[1])
                if self._key(candidate) > self._key(best):
                    best, choice = candidate, (q, no, yes)
        self.cache[state], self.choices[state] = best, choice
        return best

    def solve(self, budget):
        b = _natural(budget, "budget")
        depth = min(b, len(self.atoms) - 1, len(self.queries))
        before = self.total_states
        score, leaves = self._solve(self.root, depth)

        def build(mask, d):
            ids = tuple(sorted(i for atom in _indices(mask) for i in self.atoms[atom]))
            choice = self.choices[(mask, d)]
            if choice is None:
                return DecisionNode(ids)
            q, no, yes = choice
            return DecisionNode(ids, q, build(no, d - 1), build(yes, d - 1))

        return OptimalDisclosure(self.objective, b, float(self.p.max()),
                                 min(1.0, score / self.denominator), leaves, len(self.atoms),
                                 min(1.0, sum(self.weights) / self.denominator),
                                 self.total_states - before, build(self.root, depth))


def optimal_disclosure(answer_matrix: np.ndarray, budget: int,
                       prior: Optional[Sequence[float]] = None,
                       objective: str = "guessing", max_states: int = 200_000) -> OptimalDisclosure:
    """Exact finite-pool optimum; compatibility wrapper around DisclosureSolver.

    For repeated budgets use one DisclosureSolver to retain the memoised states.
    Both outcomes cost one slot. Uniform guessing success equals capacity/M;
    with a skewed prior, capacity and guessing are separate objectives.
    """
    return DisclosureSolver(answer_matrix, prior, objective, max_states).solve(budget)
