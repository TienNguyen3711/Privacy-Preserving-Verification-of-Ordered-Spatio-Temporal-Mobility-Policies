"""zkmob: plaintext reference semantics, data loading and leakage simulation
for Paper 3 (ZK verification of ordered spatio-temporal mobility policies).

The Rust circuits in ../rust must agree with `zkmob.policy.evaluate`, which
is the ground truth for every experiment.
"""

from .trajectory import Point, load_geolife_plt, synthetic_diagonal, random_grid_walk
from .policy import Box, Visit, Ordered, Avoid, Dwell, Policy, evaluate, policy_from_dict

__all__ = [
    "Point", "load_geolife_plt", "synthetic_diagonal", "random_grid_walk",
    "Box", "Visit", "Ordered", "Avoid", "Dwell", "Policy", "evaluate", "policy_from_dict",
]
