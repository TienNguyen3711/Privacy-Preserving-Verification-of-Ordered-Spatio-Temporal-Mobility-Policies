//! JSON bridge from the Python side (`zkmob.bridge`). Formats:
//!
//! Trace   `{"points": [[x, y, t], ...]}`  (planar metres, seconds, time-sorted)
//! Policy  `{"steps": [{"zone": {"xmin":..,"xmax":..,"ymin":..,"ymax":..},
//!                      "max_gap": 900 | null}, ...],
//!           "avoid": {...} | null}`
//! Batch   one JSON object per line: a policy plus `"id"`, `"dataset"`,
//!         `"points"`, `"expected"` (Python's `evaluate`) and free-form `"meta"`.
//!
//! This is the circuit-level policy form: one ordered clause plus at most one
//! avoid zone. `zkmob.bridge.to_circuit_policy` compiles the richer Python
//! policy language into it and rejects what the circuit cannot express yet.

use serde::{Deserialize, Serialize};

use crate::types::{BoxZone, Point, Step};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ZoneJson {
    pub xmin: u64,
    pub xmax: u64,
    pub ymin: u64,
    pub ymax: u64,
}

impl From<ZoneJson> for BoxZone {
    fn from(z: ZoneJson) -> Self {
        BoxZone { xmin: z.xmin, xmax: z.xmax, ymin: z.ymin, ymax: z.ymax }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepJson {
    pub zone: ZoneJson,
    #[serde(default)]
    pub max_gap: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyJson {
    pub steps: Vec<StepJson>,
    #[serde(default)]
    pub avoid: Option<ZoneJson>,
}

impl PolicyJson {
    pub fn steps(&self) -> Vec<Step> {
        self.steps.iter().map(|s| Step { zone: s.zone.into(), max_gap: s.max_gap }).collect()
    }
    pub fn avoid(&self) -> Option<BoxZone> {
        self.avoid.map(Into::into)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TraceJson {
    pub points: Vec<[u64; 3]>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BatchItem {
    pub id: String,
    pub dataset: String,
    pub points: Vec<[u64; 3]>,
    #[serde(flatten)]
    pub policy: PolicyJson,
    pub expected: bool,
    #[serde(default)]
    pub meta: serde_json::Value,
}

pub fn to_points(rows: &[[u64; 3]]) -> Vec<Point> {
    rows.iter().map(|r| Point { x: r[0], y: r[1], t: r[2] }).collect()
}

/// Reject inputs that violate the circuit's assumptions (same checks as
/// Python `trajectory.validate`).
pub fn validate(traj: &[Point]) -> Result<(), String> {
    use crate::types::{COORD_BITS, TIME_BITS};
    if traj.is_empty() {
        return Err("empty trajectory".into());
    }
    for (i, p) in traj.iter().enumerate() {
        if p.x >= 1 << COORD_BITS || p.y >= 1 << COORD_BITS || p.t >= 1 << TIME_BITS {
            return Err(format!("point {i} out of circuit range"));
        }
        if i > 0 && p.t < traj[i - 1].t {
            return Err(format!("trajectory not time-sorted at {i}"));
        }
    }
    Ok(())
}
