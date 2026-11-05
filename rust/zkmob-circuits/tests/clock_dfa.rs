//! BL-clockDFA: exact-time automaton baseline (claim C1, review item 7).

use ark_bn254::Fr;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use zkmob_circuits::automaton::{clock_constraints, clock_dfa_accepts, ClockDfaCircuit};
use zkmob_circuits::budget::{scan_eval, ScanPolicyCircuit};
use zkmob_circuits::synth::count;
use zkmob_circuits::types::{find_witness, BoxZone, Point, Step};

fn rand_box(rng: &mut StdRng) -> BoxZone {
    let (x, y) = (rng.gen_range(0..8u64), rng.gen_range(0..8u64));
    BoxZone { xmin: x, xmax: x + rng.gen_range(0..4), ymin: y, ymax: y + rng.gen_range(0..4) }
}

fn rand_case(rng: &mut StdRng) -> (Vec<Point>, Vec<Step>, Option<BoxZone>) {
    let n = rng.gen_range(1..14);
    let mut t = 0u64;
    let traj = (0..n)
        .map(|_| {
            t += rng.gen_range(0..20); // duplicate timestamps allowed
            Point { x: rng.gen_range(0..10), y: rng.gen_range(0..10), t }
        })
        .collect();
    let k = rng.gen_range(1..5);
    let steps = (0..k)
        .map(|s| Step { zone: rand_box(rng), max_gap: if s > 0 && rng.gen_bool(0.7) { Some(rng.gen_range(0..40)) } else { None } })
        .collect();
    let avoid = if rng.gen_bool(0.3) { Some(rand_box(rng)) } else { None };
    (traj, steps, avoid)
}

#[test]
fn clock_dfa_matches_reference_semantics() {
    // `find_witness` is the Rust reference semantics; it is cross-checked
    // against Python `policy.evaluate` on every real policy by `n1_real`.
    let mut rng = StdRng::seed_from_u64(21);
    let (mut yes, mut no) = (0, 0);
    for _ in 0..5000 {
        let (traj, steps, avoid) = rand_case(&mut rng);
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        assert_eq!(clock_dfa_accepts(&traj, &steps, avoid.as_ref()), truth, "{traj:?} {steps:?} {avoid:?}");
        assert_eq!(scan_eval(&traj, &steps, avoid.as_ref()), truth);
        if truth { yes += 1 } else { no += 1 }
    }
    assert!(yes > 300 && no > 300, "both outcomes exercised ({yes} / {no})");
}

#[test]
fn clock_dfa_circuit_proves_either_outcome_exactly() {
    let mut rng = StdRng::seed_from_u64(22);
    for _ in 0..200 {
        let (traj, steps, avoid) = rand_case(&mut rng);
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        let c = |outcome| ClockDfaCircuit { traj: traj.clone(), steps: steps.clone(), avoid, outcome };
        assert!(count::<Fr, _>(c(truth)).1, "true outcome must satisfy: {traj:?} {steps:?} {avoid:?}");
        assert!(!count::<Fr, _>(c(!truth)).1, "wrong outcome must not satisfy: {traj:?} {steps:?} {avoid:?}");
    }
}

#[test]
fn clock_dfa_circuit_rejects_unsorted_trace() {
    let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
    let traj = vec![Point { x: 1, y: 1, t: 50 }, Point { x: 1, y: 1, t: 40 }];
    let steps = vec![Step { zone: z, max_gap: None }, Step { zone: z, max_gap: Some(100) }];
    for outcome in [false, true] {
        assert!(!count::<Fr, _>(ClockDfaCircuit { traj: traj.clone(), steps: steps.clone(), avoid: None, outcome }).1);
    }
}

#[test]
fn clock_cost_formula_matches_synthesis() {
    let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
    for k in 1..=5usize {
        for gapped in 0..k {
            for av in [false, true] {
                for n in [1usize, 2, 7, 33, 130] {
                    let traj: Vec<Point> = (0..n).map(|i| Point { x: 5, y: 5, t: 3 * i as u64 }).collect();
                    let steps: Vec<Step> = (0..k).map(|j| Step { zone: z, max_gap: if j >= 1 && j <= gapped { Some(99) } else { None } }).collect();
                    let avoid = av.then_some(BoxZone { xmin: 50, xmax: 60, ymin: 50, ymax: 60 });
                    let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
                    let (m, ok) = count::<Fr, _>(ClockDfaCircuit { traj, steps, avoid, outcome: truth });
                    assert!(ok);
                    assert_eq!(m, clock_constraints(n, k, gapped, av), "clock n={n} k={k} gapped={gapped} avoid={av}");
                }
            }
        }
    }
    // The count does not depend on the data: random cases hit the formula too.
    let mut rng = StdRng::seed_from_u64(23);
    for _ in 0..100 {
        let (traj, steps, avoid) = rand_case(&mut rng);
        let gapped = steps.iter().filter(|s| s.max_gap.is_some()).count();
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        let (n, k) = (traj.len(), steps.len());
        let (m, _) = count::<Fr, _>(ClockDfaCircuit { traj, steps, avoid, outcome: truth });
        assert_eq!(m, clock_constraints(n, k, gapped, avoid.is_some()));
    }
}

#[test]
fn clock_dfa_costs_about_as_much_as_the_scan() {
    // Same public interface and either-outcome semantics as the scan; at
    // the n1 workload shape (A, then B within a gap) it is within 1%.
    let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
    for n in [32usize, 128, 863] {
        let traj: Vec<Point> = (0..n).map(|i| Point { x: 5, y: 5, t: i as u64 }).collect();
        let steps = vec![Step { zone: z, max_gap: None }, Step { zone: z, max_gap: Some(99) }];
        let (scan, _) = count::<Fr, _>(ScanPolicyCircuit { traj, steps, avoid: None, outcome: true });
        let clock = clock_constraints(n, 2, 1, false);
        assert!(clock > scan && (clock as f64) < 1.01 * scan as f64, "n={n}: clock {clock} vs scan {scan}");
    }
}
