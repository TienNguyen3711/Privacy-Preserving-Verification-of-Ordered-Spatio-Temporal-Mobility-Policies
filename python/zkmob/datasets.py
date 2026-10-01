"""Real mobility datasets -> integer trips in the circuit's conventions.

Supported (all under ``code/data``, not redistributed):

* GeoLife 1.3   ``Geolife Trajectories 1.3/Data/<user>/Trajectory/*.plt``
                lat,lon,0,alt_ft,days,date,time  (GMT, 1-5 s sampling)
* T-Drive       ``T-drive Taxi Trajectories/taxi_log_2008_by_id/<id>.txt``
                id,datetime,lon,lat  (note: lon first; ~3 min sampling)
* Porto (ECML/PKDD 2015)  ``porto_taxi/train.csv``, one trip per row,
                POLYLINE = [[lon,lat],...] every 15 s from TIMESTAMP

Every trip is projected to planar metres around a fixed city origin
(equirectangular, offset so coordinates are non-negative), timestamps are
seconds from the trip start, and the absolute start time is kept for
time-based train/test splits. Cleaning rules (applied identically to all
datasets, reported in the paper):

1. drop fixes outside the city window (``City.half_m`` around the origin);
2. drop duplicate timestamps and fixes implying > ``MAX_SPEED`` m/s;
3. split at time gaps > ``gap_s``; cut segments longer than ``max_dur_s``
   into consecutive windows;
4. keep trips with >= ``min_points`` fixes and >= ``min_dur_s`` seconds.
"""

from __future__ import annotations

import calendar
import csv
import json
import math
import os
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .trajectory import Point, validate

DATA_ROOT = Path(__file__).resolve().parents[2] / "data"
GEOLIFE_DIR = "Geolife Trajectories 1.3/Data"
TDRIVE_DIR = "T-drive Taxi Trajectories/taxi_log_2008_by_id"
PORTO_CSV = "porto_taxi/train.csv"

MAX_SPEED = 60.0  # m/s (216 km/h): GPS jumps above this are dropped

Fix = Tuple[float, float, int]  # lat, lon, unix seconds


@dataclass(frozen=True)
class City:
    name: str
    lat0: float
    lon0: float
    half_m: int  # half side of the square window kept around the origin

    def project(self, lat: float, lon: float) -> Tuple[int, int]:
        """Local equirectangular projection, offset so the window maps to
        [0, 2 * half_m]. Error is well under 1% inside a 50 km window."""
        r = 6_371_000.0
        x = math.radians(lon - self.lon0) * r * math.cos(math.radians(self.lat0))
        y = math.radians(lat - self.lat0) * r
        return int(round(x)) + self.half_m, int(round(y)) + self.half_m

    def inside(self, x: int, y: int) -> bool:
        return 0 <= x <= 2 * self.half_m and 0 <= y <= 2 * self.half_m


BEIJING = City("beijing", 39.9042, 116.4074, 30_000)
PORTO = City("porto", 41.1579, -8.6291, 15_000)


@dataclass(frozen=True)
class SegmentRules:
    gap_s: int = 600
    min_points: int = 20
    min_dur_s: int = 600
    max_dur_s: int = 7_200
    max_points: int = 4_000


@dataclass
class Trip:
    dataset: str
    owner: str          # user id (GeoLife) or taxi id (T-Drive, Porto)
    trip_id: str
    start: int          # unix seconds of the first fix
    points: List[Point] = field(repr=False)

    @property
    def duration(self) -> int:
        return self.points[-1].t

    def __len__(self) -> int:
        return len(self.points)


# --------------------------------------------------------------------------
# Cleaning and segmentation (shared by all datasets)
# --------------------------------------------------------------------------

def segment(fixes: Sequence[Fix], city: City, rules: SegmentRules) -> List[List[Tuple[int, int, int]]]:
    """Clean time-sorted fixes and cut them into trips of (x, y, unix_t)."""
    kept: List[Tuple[int, int, int]] = []
    for lat, lon, ts in fixes:
        x, y = city.project(lat, lon)
        if not city.inside(x, y):
            continue
        if kept:
            px, py, pt = kept[-1]
            if ts <= pt:
                continue
            if math.hypot(x - px, y - py) / (ts - pt) > MAX_SPEED:
                continue
        kept.append((x, y, ts))

    segs: List[List[Tuple[int, int, int]]] = []
    cur: List[Tuple[int, int, int]] = []
    for p in kept:
        if cur and (p[2] - cur[-1][2] > rules.gap_s or p[2] - cur[0][2] > rules.max_dur_s):
            segs.append(cur)
            cur = []
        cur.append(p)
    if cur:
        segs.append(cur)
    return [s for s in segs
            if len(s) >= rules.min_points and s[-1][2] - s[0][2] >= rules.min_dur_s and len(s) <= rules.max_points]


def _to_trip(dataset: str, owner: str, trip_id: str, seg: List[Tuple[int, int, int]]) -> Trip:
    t0 = seg[0][2]
    pts = [Point(x, y, t - t0) for x, y, t in seg]
    validate(pts)
    return Trip(dataset, owner, trip_id, t0, pts)


# --------------------------------------------------------------------------
# GeoLife
# --------------------------------------------------------------------------

def read_plt(path: str | Path) -> List[Fix]:
    out: List[Fix] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i < 6:
                continue
            parts = line.strip().split(",")
            if len(parts) < 7:
                continue
            y, mo, d = (int(v) for v in parts[5].split("-"))
            hh, mm, ss = (int(v) for v in parts[6].split(":"))
            out.append((float(parts[0]), float(parts[1]), calendar.timegm((y, mo, d, hh, mm, ss))))
    out.sort(key=lambda f: f[2])
    return out


def geolife_files(root: Path = DATA_ROOT) -> Dict[str, List[Path]]:
    """user id -> sorted list of .plt files."""
    base = Path(root) / GEOLIFE_DIR
    out: Dict[str, List[Path]] = {}
    for user in sorted(os.listdir(base)):
        d = base / user / "Trajectory"
        if d.is_dir():
            out[user] = sorted(d.glob("*.plt"))
    return out


def load_geolife(root: Path = DATA_ROOT, users: Optional[Iterable[str]] = None, max_files: Optional[int] = None,
                 seed: int = 0, city: City = BEIJING, rules: SegmentRules = SegmentRules()) -> List[Trip]:
    """Trips from GeoLife. `users` restricts to those users; `max_files`
    draws a seeded random sample of .plt files (across the chosen users)."""
    files = geolife_files(root)
    chosen = [(u, f) for u in (users if users is not None else files) for f in files.get(u, [])]
    if max_files is not None and max_files < len(chosen):
        chosen = random.Random(seed).sample(chosen, max_files)
    trips: List[Trip] = []
    for user, f in chosen:
        for k, seg in enumerate(segment(read_plt(f), city, rules)):
            trips.append(_to_trip("geolife", user, f"{user}/{f.stem}/{k}", seg))
    trips.sort(key=lambda t: t.start)
    return trips


# --------------------------------------------------------------------------
# T-Drive
# --------------------------------------------------------------------------

TDRIVE_RULES = SegmentRules(gap_s=900, min_points=10, min_dur_s=600, max_dur_s=7_200)


def read_tdrive(path: str | Path) -> List[Fix]:
    out: List[Fix] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            date, time = parts[1].split(" ")
            y, mo, d = (int(v) for v in date.split("-"))
            hh, mm, ss = (int(v) for v in time.split(":"))
            out.append((float(parts[3]), float(parts[2]), calendar.timegm((y, mo, d, hh, mm, ss))))
    out.sort(key=lambda f: f[2])
    return out


def load_tdrive(root: Path = DATA_ROOT, max_taxis: Optional[int] = None, seed: int = 0, city: City = BEIJING,
                rules: SegmentRules = TDRIVE_RULES) -> List[Trip]:
    base = Path(root) / TDRIVE_DIR
    files = sorted(base.glob("*.txt"), key=lambda p: int(p.stem))
    if max_taxis is not None and max_taxis < len(files):
        files = random.Random(seed).sample(files, max_taxis)
    trips: List[Trip] = []
    for f in files:
        for k, seg in enumerate(segment(read_tdrive(f), city, rules)):
            trips.append(_to_trip("tdrive", f.stem, f"{f.stem}/{k}", seg))
    trips.sort(key=lambda t: t.start)
    return trips


# --------------------------------------------------------------------------
# Porto
# --------------------------------------------------------------------------

PORTO_RULES = SegmentRules(gap_s=60, min_points=20, min_dur_s=300, max_dur_s=7_200)


def iter_porto(path: str | Path) -> Iterator[Tuple[str, str, int, List[Fix]]]:
    """Yield (trip_id, taxi_id, start, fixes) for complete trips, in file order."""
    csv.field_size_limit(sys.maxsize)
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row["MISSING_DATA"] != "False":
                continue
            poly = json.loads(row["POLYLINE"])
            if not poly:
                continue
            t0 = int(row["TIMESTAMP"])
            yield row["TRIP_ID"], row["TAXI_ID"], t0, [(lat, lon, t0 + 15 * i) for i, (lon, lat) in enumerate(poly)]


def load_porto(root: Path = DATA_ROOT, max_rows: Optional[int] = 50_000, city: City = PORTO,
               rules: SegmentRules = PORTO_RULES) -> List[Trip]:
    """First `max_rows` complete trips of train.csv (the file is roughly
    chronological, so this is a contiguous time period)."""
    trips: List[Trip] = []
    for n, (tid, taxi, t0, fixes) in enumerate(iter_porto(Path(root) / PORTO_CSV)):
        if max_rows is not None and n >= max_rows:
            break
        # a Porto row is already one trip: drop it if cleaning splits it
        segs = segment(fixes, city, rules)
        if len(segs) == 1 and len(segs[0]) == len(fixes):
            trips.append(_to_trip("porto", taxi, tid, segs[0]))
    trips.sort(key=lambda t: t.start)
    return trips


def load(dataset: str, **kw) -> List[Trip]:
    return {"geolife": load_geolife, "tdrive": load_tdrive, "porto": load_porto}[dataset](**kw)


def time_split(trips: Sequence[Trip], train_frac: float = 0.7) -> Tuple[List[Trip], List[Trip]]:
    """Chronological split: the earliest `train_frac` of trips (by start
    time) form the history, the rest the evaluation period."""
    s = sorted(trips, key=lambda t: t.start)
    k = int(len(s) * train_frac)
    return s[:k], s[k:]


def describe(trips: Sequence[Trip]) -> Dict[str, float]:
    import statistics as st
    if not trips:
        return {"trips": 0}
    n = [len(t) for t in trips]
    d = [t.duration for t in trips]
    per = [t.duration / max(len(t) - 1, 1) for t in trips]
    return {"trips": len(trips), "owners": len({t.owner for t in trips}),
            "points_median": st.median(n), "points_max": max(n),
            "duration_median_s": st.median(d), "sampling_median_s": round(st.median(per), 1)}


if __name__ == "__main__":
    for name, kw in [("geolife", {"max_files": 300}), ("tdrive", {"max_taxis": 100}), ("porto", {"max_rows": 5_000})]:
        print(name, describe(load(name, **kw)))
