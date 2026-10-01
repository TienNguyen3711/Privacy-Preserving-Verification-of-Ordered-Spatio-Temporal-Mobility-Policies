//! Plain data types shared by the circuits and the native reference checks.
//!
//! Coordinates are planar metres (e.g. a local UTM / EPSG projection) stored as
//! unsigned integers, and timestamps are seconds since the start of the
//! reporting period. Both must fit in `COORD_BITS` / `TIME_BITS` bits; the
//! circuits range-check every value they use so that field wrap-around cannot
//! be abused by a malicious prover.

/// Bit width of planar coordinates (metres). 2^32 m covers any country.
pub const COORD_BITS: usize = 32;
/// Bit width of timestamps (seconds). 2^32 s is about 136 years.
pub const TIME_BITS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: u64,
    pub y: u64,
    pub t: u64,
}

/// Axis-aligned rectangular zone. Polygons (via lookup tables or triangle
/// fans) are a later extension; boxes keep the pilot's cost model simple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoxZone {
    pub xmin: u64,
    pub xmax: u64,
    pub ymin: u64,
    pub ymax: u64,
}

impl BoxZone {
    pub fn contains(&self, p: &Point) -> bool {
        self.xmin <= p.x && p.x <= self.xmax && self.ymin <= p.y && p.y <= self.ymax
    }
}

/// One step of an ordered policy: "visit `zone`", optionally "no later than
/// `max_gap` seconds after the previous step".
#[derive(Clone, Copy, Debug)]
pub struct Step {
    pub zone: BoxZone,
    pub max_gap: Option<u64>,
}

/// Native (plaintext) semantics of an ordered policy with optional avoidance:
/// there exist indices i_1 < i_2 < ... < i_k such that point i_s lies in the
/// zone of step s, t(i_s) >= t(i_{s-1}), t(i_s) - t(i_{s-1}) <= max_gap_s,
/// and no point of the trajectory lies inside `avoid`.
/// Returns a witness (the chosen indices) when the policy holds.
pub fn find_witness(traj: &[Point], steps: &[Step], avoid: Option<&BoxZone>) -> Option<Vec<usize>> {
    if let Some(z) = avoid {
        if traj.iter().any(|p| z.contains(p)) {
            return None;
        }
    }
    fn rec(traj: &[Point], steps: &[Step], s: usize, start: usize, prev: Option<usize>, out: &mut Vec<usize>) -> bool {
        if s == steps.len() {
            return true;
        }
        for i in start..traj.len() {
            if !steps[s].zone.contains(&traj[i]) {
                continue;
            }
            if let Some(pi) = prev {
                let (tp, ti) = (traj[pi].t, traj[i].t);
                if ti < tp {
                    continue;
                }
                if let Some(g) = steps[s].max_gap {
                    if ti - tp > g {
                        // later points only get later (traces are time-sorted)
                        break;
                    }
                }
            }
            out.push(i);
            if rec(traj, steps, s + 1, i + 1, Some(i), out) {
                return true;
            }
            out.pop();
        }
        false
    }
    let mut out = Vec::new();
    if rec(traj, steps, 0, 0, None, &mut out) { Some(out) } else { None }
}
