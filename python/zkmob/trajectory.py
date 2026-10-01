"""Trajectories as time-sorted lists of planar points (metres, seconds).

Same conventions as the Rust side (rust/zkmob-circuits/src/types.rs):
non-negative integer coordinates below 2**32 and integer timestamps measured
from the start of the reporting period.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

COORD_BITS = 32
TIME_BITS = 32


@dataclass(frozen=True)
class Point:
    x: int
    y: int
    t: int

    def check_range(self) -> None:
        if not (0 <= self.x < 2**COORD_BITS and 0 <= self.y < 2**COORD_BITS and 0 <= self.t < 2**TIME_BITS):
            raise ValueError(f"point out of circuit range: {self}")


def validate(traj: List[Point]) -> None:
    """Raise if the trajectory violates the circuit's input assumptions."""
    for p in traj:
        p.check_range()
    for a, b in zip(traj, traj[1:]):
        if b.t < a.t:
            raise ValueError("trajectory must be time-sorted")


def synthetic_diagonal(horizon: int = 3600, period: int = 5) -> List[Point]:
    """Mirror of rust `scenario::diagonal`: straight 8 km diagonal drive."""
    x0, y0, x1, y1 = 1000, 1000, 9000, 9000
    pts = []
    for i in range(horizon // period):
        t = i * period
        f = t / horizon
        pts.append(Point(x0 + int((x1 - x0) * f), y0 + int((y1 - y0) * f), t))
    return pts


def random_grid_walk(
    grid: int, cell_m: int, steps: int, step_s: int, rng: random.Random, start: Optional[Tuple[int, int]] = None
) -> List[Point]:
    """Random walk on a grid of `grid` x `grid` cells (4-neighbour moves,
    may pause). Points are cell centres. Used by the leakage simulation."""
    cx, cy = start if start else (rng.randrange(grid), rng.randrange(grid))
    pts = []
    for i in range(steps):
        pts.append(Point(cx * cell_m + cell_m // 2, cy * cell_m + cell_m // 2, i * step_s))
        dx, dy = rng.choice([(1, 0), (-1, 0), (0, 1), (0, -1), (0, 0)])
        cx = min(max(cx + dx, 0), grid - 1)
        cy = min(max(cy + dy, 0), grid - 1)
    return pts


# --------------------------------------------------------------------------
# GeoLife (Microsoft Research Asia) .plt loader. Download the dataset
# yourself; it is not redistributed here.
# Format: 6 header lines, then lat,lon,0,alt_ft,days,date,time
# --------------------------------------------------------------------------

def _project(lat: float, lon: float, lat0: float, lon0: float) -> Tuple[float, float]:
    """Local equirectangular projection to metres around (lat0, lon0).
    Accurate to well under 1% within a city; swap for a proper UTM / EPSG
    projection (pyproj) for the final experiments."""
    r = 6_371_000.0
    x = math.radians(lon - lon0) * r * math.cos(math.radians(lat0))
    y = math.radians(lat - lat0) * r
    return x, y


def load_geolife_plt(
    path: str | Path, origin: Optional[Tuple[float, float]] = None, offset_m: int = 100_000
) -> List[Point]:
    """Load one GeoLife .plt file as a time-sorted integer trajectory.
    `origin` = (lat0, lon0) of the projection; defaults to the first fix.
    `offset_m` shifts coordinates so they stay non-negative."""
    rows: List[Tuple[float, float, datetime]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i < 6:
                continue
            parts = line.strip().split(",")
            if len(parts) < 7:
                continue
            lat, lon = float(parts[0]), float(parts[1])
            ts = datetime.strptime(parts[5] + " " + parts[6], "%Y-%m-%d %H:%M:%S")
            rows.append((lat, lon, ts))
    if not rows:
        return []
    lat0, lon0 = origin if origin else (rows[0][0], rows[0][1])
    t0 = rows[0][2]
    pts = []
    for lat, lon, ts in rows:
        x, y = _project(lat, lon, lat0, lon0)
        pts.append(Point(int(round(x)) + offset_m, int(round(y)) + offset_m, int((ts - t0).total_seconds())))
    pts.sort(key=lambda p: p.t)
    validate(pts)
    return pts


def to_rows(traj: Iterable[Point]) -> List[List[int]]:
    """JSON-friendly form, e.g. for handing a trace to the Rust prover."""
    return [[p.x, p.y, p.t] for p in traj]
