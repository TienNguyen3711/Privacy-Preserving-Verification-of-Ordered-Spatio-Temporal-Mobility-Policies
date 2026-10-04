//! The zero-knowledge STARK policy scan agrees with the native relation and
//! cannot prove a wrong outcome.

use p3_uni_stark::{prove, verify};
use zkmob_core::{scan_eval, BoxZone, Point, Policy, Step};
use zkmob_stark::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self, m: u32) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 33) as u32) % m
    }
    fn zone(&mut self) -> BoxZone {
        let (x, y) = (self.next(8), self.next(8));
        BoxZone { xmin: x, xmax: x + self.next(4), ymin: y, ymax: y + self.next(4) }
    }
}

fn case(r: &mut Rng) -> (Vec<Point>, Policy) {
    let n = 1 + r.next(12) as usize;
    let mut t = 0;
    let traj = (0..n).map(|_| { t += r.next(20); Point { x: r.next(10), y: r.next(10), t } }).collect();
    let k = 1 + r.next(3) as usize;
    let steps = (0..k).map(|s| Step { zone: r.zone(), max_gap: if s > 0 && r.next(10) < 7 { Some(r.next(40)) } else { None } }).collect();
    let avoid = if r.next(10) < 3 { Some(r.zone()) } else { None };
    (traj, Policy { steps, avoid })
}

#[test]
fn scan_stark_proves_exact_outcome_both_ways() {
    let config = zk_config();
    let mut r = Rng(3);
    let mut seen = [0, 0];
    for _ in 0..150 {
        let (traj, pol) = case(&mut r);
        let truth = scan_eval(&traj, &pol);
        seen[truth as usize] += 1;
        let air = ScanAir { layout: Layout { k: pol.steps.len(), avoid: pol.avoid.is_some() } };
        let trace = generate_trace(&traj, &pol);
        let pis = public_values(&pol, truth);
        let proof = prove(&config, &air, trace.clone(), &pis).expect("prove");
        verify(&config, &air, &proof, &pis).expect("honest proof verifies");
        // the same proof does not verify the opposite outcome
        assert!(verify(&config, &air, &proof, &public_values(&pol, !truth)).is_err());
    }
    assert!(seen[0] > 10 && seen[1] > 10, "{seen:?}");
}

#[test]
fn scan_stark_cannot_claim_wrong_outcome() {
    // A prover that uses the honest trace but claims the opposite outcome
    // fails (prove errors on unsatisfied constraints or the proof is rejected).
    let config = zk_config();
    let traj: Vec<Point> = (0..8).map(|i| Point { x: 10 * i, y: 10 * i, t: 5 * i }).collect();
    let z = |c: u32| BoxZone { xmin: c - 2, xmax: c + 2, ymin: c - 2, ymax: c + 2 };
    let pol = Policy { steps: vec![Step { zone: z(20), max_gap: None }, Step { zone: z(50), max_gap: Some(20) }], avoid: None };
    let truth = scan_eval(&traj, &pol);
    assert!(truth);
    let air = ScanAir { layout: Layout { k: 2, avoid: false } };
    let pis = public_values(&pol, !truth);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = prove(&config, &air, generate_trace(&traj, &pol), &pis).ok()?;
        verify(&config, &air, &proof, &pis).ok()
    }));
    assert!(!matches!(res, Ok(Some(()))), "a wrong outcome must not yield a valid proof");
}
