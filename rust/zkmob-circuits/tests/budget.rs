//! N5 mechanism: scan circuit (either outcome) and nullifier-based budget.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use zkmob_circuits::budget::*;
use zkmob_circuits::commit::{commit_native_hiding, poseidon_config};
use zkmob_circuits::scenario::diagonal;
use zkmob_circuits::sig::*;
use zkmob_circuits::types::{find_witness, BoxZone, Point, Step};

fn sat<C: ConstraintSynthesizer<Fr>>(c: C) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

fn rand_box(rng: &mut StdRng) -> BoxZone {
    let (x, y) = (rng.gen_range(0..8u64), rng.gen_range(0..8u64));
    BoxZone { xmin: x, xmax: x + rng.gen_range(0..4), ymin: y, ymax: y + rng.gen_range(0..4) }
}

fn rand_case(rng: &mut StdRng) -> (Vec<Point>, Vec<Step>, Option<BoxZone>) {
    let n = rng.gen_range(1..14);
    let mut t = 0u64;
    let traj = (0..n)
        .map(|_| {
            t += rng.gen_range(0..20); // duplicates allowed
            Point { x: rng.gen_range(0..10), y: rng.gen_range(0..10), t }
        })
        .collect();
    let k = rng.gen_range(1..4);
    let steps = (0..k)
        .map(|s| Step { zone: rand_box(rng), max_gap: if s > 0 && rng.gen_bool(0.7) { Some(rng.gen_range(0..40)) } else { None } })
        .collect();
    let avoid = if rng.gen_bool(0.3) { Some(rand_box(rng)) } else { None };
    (traj, steps, avoid)
}

#[test]
fn scan_matches_witness_search() {
    let mut rng = StdRng::seed_from_u64(11);
    let (mut yes, mut no) = (0, 0);
    for _ in 0..3000 {
        let (traj, steps, avoid) = rand_case(&mut rng);
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        assert_eq!(scan_eval(&traj, &steps, avoid.as_ref()), truth, "{traj:?} {steps:?} {avoid:?}");
        if truth { yes += 1 } else { no += 1 }
    }
    assert!(yes > 300 && no > 300, "both outcomes exercised ({yes} / {no})");
}

#[test]
fn scan_circuit_proves_either_outcome_exactly() {
    let mut rng = StdRng::seed_from_u64(12);
    for _ in 0..150 {
        let (traj, steps, avoid) = rand_case(&mut rng);
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        let c = |outcome| ScanPolicyCircuit { traj: traj.clone(), steps: steps.clone(), avoid, outcome };
        assert!(sat(c(truth)), "true outcome must be provable");
        assert!(!sat(c(!truth)), "false outcome must not be provable");
    }
}

#[test]
fn scan_circuit_rejects_unsorted_trace() {
    let traj = vec![Point { x: 1, y: 1, t: 10 }, Point { x: 5, y: 5, t: 5 }];
    let steps = vec![Step { zone: BoxZone { xmin: 0, xmax: 2, ymin: 0, ymax: 2 }, max_gap: None }];
    for outcome in [true, false] {
        assert!(!sat(ScanPolicyCircuit { traj: traj.clone(), steps: steps.clone(), avoid: None, outcome }));
    }
}

struct Setup {
    h: Hasher<Fr>,
    registry: Registry<Fr>,
    dev: Device<Fr>,
    reg_index: usize,
}

fn setup() -> Setup {
    let h = Hasher::<Fr>::new();
    let m = mldsa_from_seed([1u8; 32]);
    let mut registry = Registry::new(&h, 4);
    let mut dev = Device::manufacture([2u8; 32], [3u8; 32], 2, &m);
    let id = registry.enroll(&dev.vk_bytes(), &dev.cert, &mldsa_vk(&m)).unwrap();
    let ec = dev.new_epoch(&h);
    let reg_index = registry.register_epoch(&h, id, &ec).unwrap();
    Setup { h, registry, dev, reg_index }
}

#[test]
fn budget_slots_nullifiers_and_log() {
    let mut s = setup();
    let sc = diagonal(300, 10);
    let blind = 99u128;
    let c = commit_native_hiding(&poseidon_config::<Fr>(), &sc.traj, blind);
    let sig = s.dev.sign(&s.h, &c).unwrap();
    let (v1, v2) = (Fr::from(501u64), Fr::from(502u64));
    let budget = 3u64;
    let circ = |steps: Vec<Step>, outcome: bool, v: Fr, slot: u64| BudgetedCircuit {
        traj: sc.traj.clone(), steps, avoid: None, outcome, blind, sig: sig.clone(), reg_index: s.reg_index,
        reg_path: s.registry.path(s.reg_index), reg_root: s.registry.root(), verifier: v, budget, slot,
    };
    let yes = sc.two_step(200);
    let no = sc.two_step(30);
    assert!(find_witness(&sc.traj, &yes, None).is_some() && find_witness(&sc.traj, &no, None).is_none());

    // both answers are provable (and the wrong one is not)
    assert!(sat(circ(yes.clone(), true, v1, 0)));
    assert!(sat(circ(no.clone(), false, v1, 1)));
    assert!(!sat(circ(no.clone(), true, v1, 1)), "cannot claim a false policy holds");
    assert!(!sat(circ(yes.clone(), false, v1, 1)), "cannot deny a true policy");

    // slots: j < B only; nullifiers distinct across slots and verifiers
    assert!(sat(circ(yes.clone(), true, v1, 2)));
    assert!(!sat(circ(yes.clone(), true, v1, 3)), "slot j = B is out of budget");
    let n = |v: Fr, j: u64| circ(yes.clone(), true, v, j).nullifier(&s.h);
    let all = [n(v1, 0), n(v1, 1), n(v1, 2), n(v2, 0), n(v2, 1), n(v2, 2)];
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
    // the nullifier depends on the slot, not the policy: reuse is caught
    assert_eq!(circ(yes.clone(), true, v1, 0).nullifier(&s.h), circ(no.clone(), false, v1, 0).nullifier(&s.h));
    let mut log = NullifierLog::default();
    assert!(log.accept(&v1, &n(v1, 0)) && log.accept(&v1, &n(v1, 1)) && log.accept(&v2, &n(v2, 0)));
    assert!(!log.accept(&v1, &n(v1, 0)), "replayed slot rejected");

    // prover wallet hands out exactly B slots per (trace, verifier)
    let mut wallet = SlotWallet::default();
    let got: Vec<_> = (0..5).map(|_| wallet.next(&c, &v1, budget)).collect();
    assert_eq!(got, vec![Some(0), Some(1), Some(2), None, None]);
    assert_eq!(wallet.next(&c, &v2, budget), Some(0), "separate budget per verifier");
}

#[test]
fn budgeted_groth16_end_to_end() {
    let mut s = setup();
    let sc = diagonal(300, 10);
    let c = commit_native_hiding(&poseidon_config::<Fr>(), &sc.traj, 7);
    let sig = s.dev.sign(&s.h, &c).unwrap();
    let circ = |steps: Vec<Step>, outcome, slot| BudgetedCircuit {
        traj: sc.traj.clone(), steps, avoid: Some(sc.restricted), outcome, blind: 7, sig: sig.clone(),
        reg_index: s.reg_index, reg_path: s.registry.path(s.reg_index), reg_root: s.registry.root(),
        verifier: Fr::from(9u64), budget: 4, slot,
    };
    let mut rng = StdRng::seed_from_u64(5);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circ(sc.two_step(200), true, 0), &mut rng).unwrap();
    for (steps, outcome, slot) in [(sc.two_step(200), true, 0), (sc.two_step(30), false, 1)] {
        let cc = circ(steps, outcome, slot);
        let public = cc.public_inputs(&s.h);
        let proof = Groth16::<Bn254>::prove(&pk, cc, &mut rng).unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
        // flipping the public outcome bit breaks verification
        let mut bad = public.clone();
        let ob = bad.len() - 5;
        bad[ob] = Fr::from(!outcome as u64);
        assert!(!Groth16::<Bn254>::verify(&vk, &bad, &proof).unwrap());
    }
}
