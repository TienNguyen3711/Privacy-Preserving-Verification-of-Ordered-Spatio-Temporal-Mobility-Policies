"""Python -> JSON -> Rust bridge (roadmap step 4).

`to_circuit_policy` compiles the Python policy language into the form the
current circuit proves: ONE ordered clause (or a single Visit) plus at most
ONE Avoid zone. Anything else raises `Unsupported`, so the gap between the
policy language and the circuit (claim N2 / RQ1) stays explicit.

Demo on a real trace (writes JSON under work/ and runs the Rust prover):

    PYTHONPATH=python python3 -m zkmob.bridge --dataset geolife [--commit hiding]
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .policy import Avoid, Box, Dwell, Ordered, Policy, Step, Visit, evaluate
from .trajectory import Point, to_rows

CODE_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = CODE_ROOT / "rust" / "zkmob-circuits" / "Cargo.toml"
WORK = CODE_ROOT / "work"


class Unsupported(ValueError):
    """The policy is valid but the current circuit cannot express it."""


def box_dict(b: Box) -> Dict[str, int]:
    if min(b.xmin, b.ymin) < 0 or b.xmin > b.xmax or b.ymin > b.ymax:
        raise ValueError(f"zone must be a non-negative, non-empty box: {b}")
    return {"xmin": b.xmin, "xmax": b.xmax, "ymin": b.ymin, "ymax": b.ymax}


def to_circuit_policy(policy: Policy) -> Dict:
    ordered: List[Ordered] = [c for c in policy.clauses if isinstance(c, Ordered)]
    visits: List[Visit] = [c for c in policy.clauses if isinstance(c, Visit)]
    avoids: List[Avoid] = [c for c in policy.clauses if isinstance(c, Avoid)]
    if any(isinstance(c, Dwell) for c in policy.clauses):
        raise Unsupported("Dwell has no circuit yet")
    if len(ordered) + len(visits) != 1:
        raise Unsupported("circuit proves exactly one Ordered or Visit clause")
    if len(avoids) > 1:
        raise Unsupported("circuit supports at most one Avoid zone")
    steps = ordered[0].steps if ordered else [Step(visits[0].zone)]
    if steps[0].max_gap is not None:
        raise Unsupported("the first step cannot carry max_gap")
    return {
        "steps": [{"zone": box_dict(s.zone), "max_gap": s.max_gap} for s in steps],
        "avoid": box_dict(avoids[0].zone) if avoids else None,
    }


def from_circuit_policy(spec: Dict) -> Policy:
    """Inverse of `to_circuit_policy` (used by tests and batch checks)."""
    bx = lambda d: Box(d["xmin"], d["xmax"], d["ymin"], d["ymax"])  # noqa: E731
    clauses: list = [Ordered([Step(bx(s["zone"]), s.get("max_gap")) for s in spec["steps"]])]
    if spec.get("avoid"):
        clauses.append(Avoid(bx(spec["avoid"])))
    return Policy(clauses)


def write_json(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))
    return path


def prove(traj: Sequence[Point], policy: Policy, commit: str = "hiding", run_prover: bool = True,
          tag: str = "demo") -> Dict:
    """Export trace + policy and run the Rust `prove_json` binary."""
    trace_p = write_json(WORK / f"{tag}_trace.json", {"points": to_rows(traj)})
    policy_p = write_json(WORK / f"{tag}_policy.json", to_circuit_policy(policy))
    cmd = ["cargo", "run", "--release", "-q", "--manifest-path", str(MANIFEST), "--bin", "prove_json", "--",
           "--trace", str(trace_p), "--policy", str(policy_p), "--commit", commit]
    if not run_prover:
        cmd.append("--no-prove")
    out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    res = json.loads(out.stdout)
    res["python_evaluate"] = evaluate(policy, traj)
    return res


def around(p: Point, half: int) -> Box:
    return Box(max(p.x - half, 0), p.x + half, max(p.y - half, 0), p.y + half)


def demo_policy(traj: Sequence[Point], rng: random.Random, half: int = 100) -> Policy:
    """A policy that holds on `traj`: visit A (near 20% of the trip), then B
    (near 60%) within the observed gap + 60 s, while avoiding a zone 5 km
    away from every fix."""
    i, j = len(traj) // 5, (3 * len(traj)) // 5
    a, b = traj[i], traj[j]
    xs, ys = [p.x for p in traj], [p.y for p in traj]
    z = Box(max(xs) + 5_000, max(xs) + 6_000, max(ys) + 5_000, max(ys) + 6_000)
    return Policy([Ordered([Step(around(a, half)), Step(around(b, half), b.t - a.t + 60)]), Avoid(z)])


def main() -> None:
    from .datasets import describe, load

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="geolife", choices=["geolife", "tdrive", "porto"])
    ap.add_argument("--commit", default="hiding", choices=["off", "binding", "hiding"])
    ap.add_argument("--max-points", type=int, default=1_000)
    ap.add_argument("--no-prove", action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()

    kw = {"geolife": {"max_files": 40, "seed": a.seed}, "tdrive": {"max_taxis": 20, "seed": a.seed},
          "porto": {"max_rows": 2_000}}[a.dataset]
    trips = [t for t in load(a.dataset, **kw) if len(t) <= a.max_points]
    rng = random.Random(a.seed)
    trip = rng.choice(trips)
    pol = demo_policy(trip.points, rng)
    print(f"{a.dataset}: {describe(trips)}")
    print(f"trip {trip.trip_id}: {len(trip)} points, {trip.duration} s")
    res = prove(trip.points, pol, commit=a.commit, run_prover=not a.no_prove, tag=f"demo_{a.dataset}")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
