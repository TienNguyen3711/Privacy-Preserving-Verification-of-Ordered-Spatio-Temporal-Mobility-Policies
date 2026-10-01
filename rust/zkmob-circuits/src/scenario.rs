//! Deterministic synthetic scenario used by the pilot and the tests.
//! A vehicle drives a straight 8 km diagonal across a 10 km x 10 km area
//! over `horizon` seconds, sampled every `period` seconds. Zone A sits at
//! 20% of the route and zone B at 40%, so A -> B happens ~0.2 * horizon apart.
//! Real traces (GeoLife, T-Drive, Porto) plug in through the Python side.

use crate::types::{BoxZone, Point, Step};

pub struct Scenario {
    pub traj: Vec<Point>,
    pub zone_a: BoxZone,
    pub zone_b: BoxZone,
    pub restricted: BoxZone,
    pub horizon: u64,
}

pub fn diagonal(horizon: u64, period: u64) -> Scenario {
    let n = (horizon / period) as usize;
    let (x0, y0, x1, y1) = (1_000u64, 1_000u64, 9_000u64, 9_000u64);
    let traj: Vec<Point> = (0..n)
        .map(|i| {
            let t = i as u64 * period;
            let f = t as f64 / horizon as f64;
            Point {
                x: x0 + ((x1 - x0) as f64 * f) as u64,
                y: y0 + ((y1 - y0) as f64 * f) as u64,
                t,
            }
        })
        .collect();
    let around = |f: f64, r: u64| {
        let cx = x0 + ((x1 - x0) as f64 * f) as u64;
        let cy = y0 + ((y1 - y0) as f64 * f) as u64;
        BoxZone { xmin: cx - r, xmax: cx + r, ymin: cy - r, ymax: cy + r }
    };
    Scenario {
        traj,
        zone_a: around(0.2, 150),
        zone_b: around(0.4, 150),
        // a zone well off the diagonal
        restricted: BoxZone { xmin: 7_000, xmax: 8_000, ymin: 1_000, ymax: 2_000 },
        horizon,
    }
}

impl Scenario {
    pub fn two_step(&self, max_gap: u64) -> Vec<Step> {
        vec![
            Step { zone: self.zone_a, max_gap: None },
            Step { zone: self.zone_b, max_gap: Some(max_gap) },
        ]
    }
}
