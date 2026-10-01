"""Policy language (first draft) and its plaintext reference semantics.

A policy is a conjunction of clauses:

* ``Visit(zone)``                      some point lies in ``zone``
* ``Ordered([step, ...])``             zones visited in order; each step may
                                       carry ``max_gap`` seconds relative to
                                       the previous step (claim N1)
* ``Avoid(zone)``                      no point lies in ``zone``
* ``Dwell(zone, min_s)``               some maximal run of consecutive points
                                       inside ``zone`` spans >= ``min_s`` seconds

``evaluate`` is the ground truth the circuits must match. ``Ordered`` +
``Avoid`` match rust ``types::find_witness`` exactly (same index semantics).
``Dwell`` has no circuit yet (TODO for RQ1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Union

from .trajectory import Point


@dataclass(frozen=True)
class Box:
    xmin: int
    xmax: int
    ymin: int
    ymax: int

    def contains(self, p: Point) -> bool:
        return self.xmin <= p.x <= self.xmax and self.ymin <= p.y <= self.ymax


@dataclass(frozen=True)
class Step:
    zone: Box
    max_gap: Optional[int] = None


@dataclass(frozen=True)
class Visit:
    zone: Box


@dataclass(frozen=True)
class Ordered:
    steps: Sequence[Step]


@dataclass(frozen=True)
class Avoid:
    zone: Box


@dataclass(frozen=True)
class Dwell:
    zone: Box
    min_s: int


Clause = Union[Visit, Ordered, Avoid, Dwell]


@dataclass
class Policy:
    clauses: List[Clause] = field(default_factory=list)


def ordered_witness(traj: Sequence[Point], steps: Sequence[Step]) -> Optional[List[int]]:
    """Indices i_1 < ... < i_k witnessing the ordered clause, or None.
    Same search order as the Rust `find_witness` (first feasible, DFS)."""

    def rec(s: int, start: int, prev: Optional[int], out: List[int]) -> bool:
        if s == len(steps):
            return True
        for i in range(start, len(traj)):
            if not steps[s].zone.contains(traj[i]):
                continue
            if prev is not None:
                tp, ti = traj[prev].t, traj[i].t
                if ti < tp:
                    continue
                g = steps[s].max_gap
                if g is not None and ti - tp > g:
                    break
            out.append(i)
            if rec(s + 1, i + 1, i, out):
                return True
            out.pop()
        return False

    out: List[int] = []
    return out if rec(0, 0, None, out) else None


def _dwell(traj: Sequence[Point], zone: Box, min_s: int) -> bool:
    run_start = None
    for p in traj:
        if zone.contains(p):
            if run_start is None:
                run_start = p.t
            if p.t - run_start >= min_s:
                return True
        else:
            run_start = None
    return False


def evaluate(policy: Policy, traj: Sequence[Point]) -> bool:
    for c in policy.clauses:
        if isinstance(c, Visit):
            if not any(c.zone.contains(p) for p in traj):
                return False
        elif isinstance(c, Ordered):
            if ordered_witness(traj, c.steps) is None:
                return False
        elif isinstance(c, Avoid):
            if any(c.zone.contains(p) for p in traj):
                return False
        elif isinstance(c, Dwell):
            if not _dwell(traj, c.zone, c.min_s):
                return False
        else:  # pragma: no cover
            raise TypeError(c)
    return True


def _box(d: Dict) -> Box:
    return Box(int(d["xmin"]), int(d["xmax"]), int(d["ymin"]), int(d["ymax"]))


def policy_from_dict(spec: Dict) -> Policy:
    """Load a policy from a JSON-style dict, e.g.

    {"clauses": [
        {"ordered": [{"zone": "A"}, {"zone": "B", "max_gap": 900}]},
        {"avoid": "Z"}],
     "zones": {"A": {...}, "B": {...}, "Z": {...}}}
    """
    zones = {k: _box(v) for k, v in spec.get("zones", {}).items()}
    z = lambda ref: zones[ref] if isinstance(ref, str) else _box(ref)  # noqa: E731
    out: List[Clause] = []
    for c in spec["clauses"]:
        if "visit" in c:
            out.append(Visit(z(c["visit"])))
        elif "ordered" in c:
            out.append(Ordered([Step(z(s["zone"]), s.get("max_gap")) for s in c["ordered"]]))
        elif "avoid" in c:
            out.append(Avoid(z(c["avoid"])))
        elif "dwell" in c:
            out.append(Dwell(z(c["dwell"]["zone"]), int(c["dwell"]["min_s"])))
        else:
            raise ValueError(f"unknown clause {c}")
    return Policy(out)
