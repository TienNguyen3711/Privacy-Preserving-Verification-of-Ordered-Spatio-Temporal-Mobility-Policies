//! Pilot for claim N1: how does proof cost scale with time precision?
//!
//! Policy: "visit A, then visit B no later than MAX_GAP seconds after A".
//! * Ours: selector-based circuit, timestamps compared as 32-bit integers.
//! * B3:   resample into buckets of width w, classify each bucket, run a
//!         (k+2)-state DFA with k = ceil(MAX_GAP / w).
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml \
//!       --bin pilot_n1 -- [--prove] [--out results/pilot_n1.csv]

use std::fs::File;
use std::io::Write;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use zkmob_circuits::commit::Commit;
use zkmob_circuits::automaton::{dfa_accepts, resample, BucketAutomatonCircuit};
use zkmob_circuits::ordered::OrderedPolicyCircuit;
use zkmob_circuits::scenario::diagonal;
use zkmob_circuits::synth::count;
use zkmob_circuits::types::find_witness;

const HORIZON: u64 = 3_600; // one hour
const PERIOD: u64 = 5; // GPS sample every 5 s -> n = 720
const MAX_GAP: u64 = 900; // B within 15 min of A

struct Row {
    design: &'static str,
    commit: &'static str,
    n_points: usize,
    bucket_s: u64,
    steps: usize,
    dfa_states: usize,
    constraints: usize,
    satisfied: bool,
    prove_ms: Option<u128>,
    verify_ms: Option<u128>,
}

fn groth<C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone>(c: C, public: Vec<Fr>) -> (u128, u128) {
    let mut rng = StdRng::seed_from_u64(7);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
    let t0 = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
    let p = t0.elapsed().as_millis();
    let t1 = Instant::now();
    assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    (p, t1.elapsed().as_millis())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prove = args.iter().any(|a| a == "--prove");
    let out = args
        .iter()
        .position(|a| a == "--out")
        .map(|i| args[i + 1].clone())
        .unwrap_or_else(|| "results/pilot_n1.csv".into());

    let sc = diagonal(HORIZON, PERIOD);
    let steps = sc.two_step(MAX_GAP);
    let wit = find_witness(&sc.traj, &steps, None).expect("scenario satisfies the policy");
    let mut rows = Vec::new();

    // --- Ours: independent of time precision ---------------------------
    // Hiding commitment with a fixed blinding value (the count does not
    // depend on its value; a device draws it fresh per trace).
    let modes = [("off", Commit::Off), ("hiding", Commit::Hiding(0x5eed_u128 << 64 | 0xb1d))];
    for (commit, mode) in modes {
        let c = OrderedPolicyCircuit {
            traj: sc.traj.clone(),
            steps: steps.clone(),
            avoid: None,
            witness: Some(wit.clone()),
            commit: mode,
        };
        let (m, ok) = count::<Fr, _>(c.clone());
        let pv = if prove { Some(groth(c.clone(), c.public_inputs::<Fr>())) } else { None };
        rows.push(Row { design: "ours", commit, n_points: sc.traj.len(), bucket_s: 1, steps: 2, dfa_states: 0,
            constraints: m, satisfied: ok, prove_ms: pv.map(|x| x.0), verify_ms: pv.map(|x| x.1) });
        eprintln!("ours commit={commit}: {m} constraints, satisfied={ok}");
    }

    // --- B3: discretise + DFA, sweep bucket width ----------------------
    let prove_widths = [60u64, 15];
    for w in [600u64, 300, 180, 120, 60, 30, 15, 10, 5] {
        let sym = resample(&sc.traj, w, HORIZON);
        let k = MAX_GAP.div_ceil(w) as usize;
        let accepts = dfa_accepts(&sym, &sc.zone_a, &sc.zone_b, k);
        for (commit, mode) in modes {
            let c = BucketAutomatonCircuit { symbols: sym.clone(), zone_a: sc.zone_a, zone_b: sc.zone_b, k, commit: mode };
            let (m, ok) = count::<Fr, _>(c.clone());
            let pv = if prove && mode == Commit::Off && prove_widths.contains(&w) && ok {
                Some(groth(c.clone(), c.public_inputs::<Fr>()))
            } else {
                None
            };
            rows.push(Row { design: "b3_bucket_dfa", commit, n_points: sc.traj.len(), bucket_s: w, steps: sym.len(),
                dfa_states: k + 2, constraints: m, satisfied: ok, prove_ms: pv.map(|x| x.0), verify_ms: pv.map(|x| x.1) });
            eprintln!("b3 w={w:>3}s L={:>4} states={:>4} commit={commit}: {m} constraints, satisfied={ok} (native dfa {accepts})", sym.len(), k + 2);
        }
    }

    // --- Ours: scaling with trajectory length --------------------------
    for period in [30u64, 15, 10, 5, 2, 1] {
        let s2 = diagonal(HORIZON, period);
        let st = s2.two_step(MAX_GAP);
        let w2 = find_witness(&s2.traj, &st, None).expect("policy holds");
        let c = OrderedPolicyCircuit { traj: s2.traj.clone(), steps: st, avoid: None, witness: Some(w2), commit: Commit::Off };
        let (m, ok) = count::<Fr, _>(c);
        rows.push(Row { design: "ours_scaling_n", commit: "off", n_points: s2.traj.len(), bucket_s: 1, steps: 2, dfa_states: 0,
            constraints: m, satisfied: ok, prove_ms: None, verify_ms: None });
        eprintln!("ours n={:>5}: {m} constraints", s2.traj.len());
    }

    std::fs::create_dir_all(std::path::Path::new(&out).parent().unwrap()).ok();
    let mut f = File::create(&out).expect("write csv");
    writeln!(f, "design,commitment,n_points,time_resolution_s,circuit_steps,dfa_states,constraints,satisfied,prove_ms,verify_ms").unwrap();
    for r in rows {
        writeln!(f, "{},{},{},{},{},{},{},{},{},{}", r.design, r.commit, r.n_points, r.bucket_s, r.steps, r.dfa_states,
            r.constraints, r.satisfied, r.prove_ms.map(|v| v.to_string()).unwrap_or_default(),
            r.verify_ms.map(|v| v.to_string()).unwrap_or_default()).unwrap();
    }
    eprintln!("wrote {out}");
}
