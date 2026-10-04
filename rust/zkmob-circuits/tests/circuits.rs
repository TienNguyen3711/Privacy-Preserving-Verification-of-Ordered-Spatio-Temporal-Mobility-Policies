use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use zkmob_circuits::commit::Commit;
use zkmob_circuits::automaton::{dfa_accepts, resample, BucketAutomatonCircuit};
use zkmob_circuits::ordered::OrderedPolicyCircuit;
use zkmob_circuits::scenario::diagonal;
use zkmob_circuits::synth::count;
use zkmob_circuits::types::{find_witness, BoxZone, Point, Step};

fn ordered(traj: Vec<Point>, steps: Vec<Step>, avoid: Option<BoxZone>, w: Vec<usize>, commit: Commit) -> OrderedPolicyCircuit {
    OrderedPolicyCircuit { traj, steps, avoid, witness: Some(w), commit }
}

#[test]
fn honest_witness_satisfies() {
    let sc = diagonal(600, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, Some(&sc.restricted)).expect("policy holds");
    for commit in [Commit::Off, Commit::Binding, Commit::Hiding(12345)] {
        let (_, ok) = count::<Fr, _>(ordered(sc.traj.clone(), steps.clone(), Some(sc.restricted), w.clone(), commit));
        assert!(ok, "commit={commit:?}");
    }
}

#[test]
fn wrong_order_rejected() {
    let sc = diagonal(600, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, None).unwrap();
    let swapped = vec![w[1], w[0]];
    // swapped indices point to B then A: zone check fails for both
    let (_, ok) = count::<Fr, _>(ordered(sc.traj.clone(), steps.clone(), None, swapped, Commit::Off));
    assert!(!ok);
    // same point twice violates strict index order even if zones overlapped
    let wide = BoxZone { xmin: 0, xmax: 20_000, ymin: 0, ymax: 20_000 };
    let steps2 = vec![Step { zone: wide, max_gap: None }, Step { zone: wide, max_gap: Some(10_000) }];
    let (_, ok) = count::<Fr, _>(ordered(sc.traj.clone(), steps2, None, vec![5, 5], Commit::Off));
    assert!(!ok);
}

#[test]
fn gap_exceeded_rejected() {
    let sc = diagonal(600, 10);
    // A -> B takes ~120 s in this scenario; a 30 s bound must fail
    assert!(find_witness(&sc.traj, &sc.two_step(30), None).is_none());
    let w = find_witness(&sc.traj, &sc.two_step(1_000), None).unwrap();
    let (_, ok) = count::<Fr, _>(ordered(sc.traj.clone(), sc.two_step(30), None, w, Commit::Off));
    assert!(!ok);
}

#[test]
fn avoidance_violation_rejected() {
    let sc = diagonal(600, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, None).unwrap();
    // a restricted zone that the diagonal does cross
    let crossed = BoxZone { xmin: 4_000, xmax: 6_000, ymin: 4_000, ymax: 6_000 };
    let (_, ok) = count::<Fr, _>(ordered(sc.traj.clone(), steps, Some(crossed), w, Commit::Off));
    assert!(!ok);
}

#[test]
fn automaton_matches_native_dfa() {
    let sc = diagonal(600, 10);
    // also overlapping zones (B = A grown by 300 m) to exercise the "both" symbol
    let big = BoxZone { xmin: sc.zone_a.xmin - 300, xmax: sc.zone_a.xmax + 300, ymin: sc.zone_a.ymin - 300, ymax: sc.zone_a.ymax + 300 };
    for zb in [sc.zone_b, big] {
        for (w, gap) in [(60u64, 200u64), (30, 200), (30, 60), (10, 90), (10, 20)] {
            let sym = resample(&sc.traj, w, sc.horizon);
            let k = gap.div_ceil(w) as usize;
            let expect = dfa_accepts(&sym, &sc.zone_a, &zb, k);
            let c = BucketAutomatonCircuit { symbols: sym, zone_a: sc.zone_a, zone_b: zb, k, commit: Commit::Off };
            let (_, ok) = count::<Fr, _>(c);
            assert_eq!(ok, expect, "w={w} gap={gap}");
        }
    }
}

#[test]
fn groth16_end_to_end() {
    let sc = diagonal(300, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, None).unwrap();
    let c = ordered(sc.traj.clone(), steps, None, w, Commit::Hiding(777));
    let public = c.public_inputs::<Fr>();
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
    assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    // a different commitment must not verify
    let mut bad = public.clone();
    *bad.last_mut().unwrap() += Fr::from(1u64);
    assert!(!Groth16::<Bn254>::verify(&vk, &bad, &proof).unwrap());
}

#[test]
fn hiding_commitment_randomises_and_still_verifies() {
    // Roadmap step 1: two commitments to the SAME trajectory differ, and a
    // proof against each one verifies only against its own commitment.
    let sc = diagonal(300, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, None).unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let (m1, m2) = (Commit::fresh_hiding(&mut rng), Commit::fresh_hiding(&mut rng));
    let c1: Fr = m1.value(&sc.traj).unwrap();
    let c2: Fr = m2.value(&sc.traj).unwrap();
    assert_ne!(c1, c2, "hiding commitments to one trace must differ");
    // binding mode is deterministic (this is what B2 leaks)
    assert_eq!(Commit::Binding.value::<Fr>(&sc.traj), Commit::Binding.value::<Fr>(&sc.traj));

    // one circuit-specific setup serves both (the shape does not depend on r)
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(ordered(sc.traj.clone(), steps.clone(), None, w.clone(), m1), &mut rng).unwrap();
    let mut publics = Vec::new();
    for m in [m1, m2] {
        let c = ordered(sc.traj.clone(), steps.clone(), None, w.clone(), m);
        let public = c.public_inputs::<Fr>();
        let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
        publics.push((public, proof));
    }
    // cross-check: proof 1 does not verify against commitment 2
    assert!(!Groth16::<Bn254>::verify(&vk, &publics[1].0, &publics[0].1).unwrap());
}

#[test]
fn hiding_commitment_rejects_wrong_blinding_or_trace() {
    let sc = diagonal(300, 10);
    let steps = sc.two_step(200);
    let w = find_witness(&sc.traj, &steps, None).unwrap();
    let honest = ordered(sc.traj.clone(), steps.clone(), None, w.clone(), Commit::Hiding(1));
    let c_honest: Fr = *honest.public_inputs::<Fr>().last().unwrap();

    // Synthesize with a different r (or a tampered trace) but force the
    // public commitment to the honest value: the circuit must be unsatisfied.
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    let check = |c: zkmob_circuits::ordered::OrderedPolicyCircuit| {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        // the commitment is the last public input (index 0 is the constant 1)
        let n = cs.num_instance_variables();
        cs.borrow_mut().unwrap().instance_assignment[n - 1] = c_honest;
        cs.is_satisfied().unwrap()
    };
    assert!(check(honest.clone()));
    assert!(!check(ordered(sc.traj.clone(), steps.clone(), None, w.clone(), Commit::Hiding(2))));
    let mut tampered = sc.traj.clone();
    tampered[3].x += 1;
    assert!(!check(ordered(tampered, steps, None, w, Commit::Hiding(1))));
}

#[test]
fn cost_formulas_match_synthesis() {
    use zkmob_circuits::automaton::b3_constraints;
    use zkmob_circuits::ordered::ours_constraints;
    let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
    for l in [1usize, 2, 7, 40] {
        for k in [1usize, 3, 16] {
            let symbols: Vec<Point> = (0..l).map(|i| Point { x: 100, y: 100, t: i as u64 }).collect();
            let (m, _) = count::<Fr, _>(BucketAutomatonCircuit { symbols, zone_a: z, zone_b: z, k, commit: Commit::Off });
            assert_eq!(m, b3_constraints(l, k), "B3 L={l} k={k}");
        }
    }
    for n in [3usize, 17, 64, 65, 300] {
        for s in [1usize, 2, 3] {
            for gapped in 0..s {
                let traj: Vec<Point> = (0..n).map(|i| Point { x: 5, y: 5, t: i as u64 }).collect();
                let steps: Vec<Step> = (0..s).map(|j| Step { zone: z, max_gap: if j >= 1 && j <= gapped { Some(99) } else { None } }).collect();
                let (m, ok) = count::<Fr, _>(ordered(traj, steps, None, (0..s).collect(), Commit::Off));
                assert!(ok);
                assert_eq!(m, ours_constraints(n, s, gapped), "ours n={n} s={s} gapped={gapped}");
            }
        }
    }
}

#[test]
fn binding_and_scan_costs_match_synthesis() {
    use zkmob_circuits::automaton::{binding_constraints, BucketBindingCircuit};
    let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
    for n in [1usize, 2, 9, 40] {
        let traj: Vec<Point> = (0..n).map(|i| Point { x: 5, y: 5, t: 37 * i as u64 }).collect();
        for w in [5u64, 60, 600] {
            let (m, ok) = count::<Fr, _>(BucketBindingCircuit { traj: traj.clone(), zone_a: z, zone_b: z, w, horizon: 7201 });
            assert!(ok);
            assert_eq!(m, binding_constraints(n, w, 7201), "binding n={n} w={w}");
        }
    }
}

#[test]
fn automaton_handles_overlapping_zones() {
    // A stationary trace inside a region that is both A and B: "A then B
    // within gap" holds (two different fixes), and B3 must accept it too.
    use zkmob_circuits::automaton::{bucket_flags_any, dfa_accepts_flags};
    let traj: Vec<Point> = (0..30).map(|i| Point { x: 500, y: 500, t: i * 10 }).collect();
    let z = BoxZone { xmin: 400, xmax: 600, ymin: 400, ymax: 600 };
    let steps = vec![Step { zone: z, max_gap: None }, Step { zone: z, max_gap: Some(60) }];
    assert!(find_witness(&traj, &steps, None).is_some());
    let sym = resample(&traj, 30, 300);
    assert!(dfa_accepts(&sym, &z, &z, 2));
    let (_, ok) = count::<Fr, _>(BucketAutomatonCircuit { symbols: sym, zone_a: z, zone_b: z, k: 2, commit: Commit::Off });
    assert!(ok, "circuit must agree with the native DFA on overlapping zones");
    assert!(dfa_accepts_flags(&bucket_flags_any(&traj, &z, &z, 30, 300), 2));
    // a single bucket cannot serve as both steps
    assert!(!dfa_accepts_flags(&[(true, true)], 2));
}
