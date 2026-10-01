//! Claim N5 mechanism on a real trace: one verifier with budget B sends
//! more queries than B; the prover answers each (yes OR no, proven exactly)
//! with a fresh slot until the budget is spent, then refuses; a replayed
//! proof is caught by the verifier's nullifier log. Also reports the cost
//! of the scan circuit versus the selector circuit.
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin budget_demo -- \
//!       [--traces work/n1_geolife.jsonl] [--n 128] [--budget 6] [--queries 9]

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use zkmob_circuits::budget::*;
use zkmob_circuits::commit::{commit_native_hiding, poseidon_config};
use zkmob_circuits::io::{to_points, BatchItem};
use zkmob_circuits::ordered::ours_constraints;
use zkmob_circuits::sig::*;
use zkmob_circuits::synth::count;
use zkmob_circuits::types::{find_witness, BoxZone, Point, Step};

fn arg<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter().position(|a| a == name).and_then(|i| args[i + 1].parse().ok()).unwrap_or(default)
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn load_trace(path: &str, n: usize) -> Vec<Point> {
    for line in BufReader::new(File::open(path).expect("open traces (run zkmob.n1_export first)")).lines() {
        let it: BatchItem = serde_json::from_str(&line.unwrap()).unwrap();
        if it.points.len() >= n {
            return to_points(&it.points[..n]);
        }
    }
    panic!("no trace with >= {n} points");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let traces: String = arg(&args, "--traces", "work/n1_geolife.jsonl".to_string());
    let n: usize = arg(&args, "--n", 128);
    let budget: u64 = arg(&args, "--budget", 6);
    let queries: usize = arg(&args, "--queries", 9);
    let mut rng = StdRng::seed_from_u64(2027);
    let traj = load_trace(&traces, n);

    // Device, registry, verifier.
    let h = Hasher::<Fr>::new();
    let manufacturer = mldsa_from_seed([200u8; 32]);
    let mut registry = Registry::new(&h, 20);
    let mut dev = Device::manufacture([1u8; 32], [2u8; 32], 6, &manufacturer);
    let id = registry.enroll(&dev.vk_bytes(), &dev.cert, &mldsa_vk(&manufacturer)).unwrap();
    let ec = dev.new_epoch(&h);
    let reg_index = registry.register_epoch(&h, id, &ec).unwrap();
    let blind: u128 = rng.r#gen();
    let c = commit_native_hiding(&poseidon_config::<Fr>(), &traj, blind);
    let sig = dev.sign(&h, &c).unwrap();
    let verifier = Fr::from(0x1a5u64); // an authenticated verifier id

    // Queries: "A then B within f * observed gap", f in {0.5, 1.5}: a mix of yes and no.
    let around = |q: &Point| BoxZone { xmin: q.x.saturating_sub(100), xmax: q.x + 100, ymin: q.y.saturating_sub(100), ymax: q.y + 100 };
    let qs: Vec<Vec<Step>> = (0..queries)
        .map(|q| {
            let i = rng.gen_range(0..n - 10);
            let j = rng.gen_range(i + 1..n);
            let dt = traj[j].t - traj[i].t;
            let f = if q % 2 == 0 { 1.5 } else { 0.5 };
            vec![Step { zone: around(&traj[i]), max_gap: None }, Step { zone: around(&traj[j]), max_gap: Some((dt as f64 * f) as u64) }]
        })
        .collect();
    let circ = |steps: &Vec<Step>, slot: u64| {
        let outcome = scan_eval(&traj, steps, None);
        BudgetedCircuit {
            traj: traj.clone(), steps: steps.clone(), avoid: None, outcome, blind, sig: sig.clone(), reg_index,
            reg_path: registry.path(reg_index), reg_root: registry.root(), verifier, budget, slot,
        }
    };

    let (m, ok) = count::<Fr, _>(circ(&qs[0], 0));
    assert!(ok);
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circ(&qs[0], 0), &mut rng).unwrap();
    let setup = ms(t);
    eprintln!("budgeted circuit (n = {n}, 2-step policy): {m} constraints, setup {setup:.0} ms; B = {budget}, {queries} queries\n");

    let mut wallet = SlotWallet::default();
    let mut log = NullifierLog::default();
    let mut rows = Vec::new();
    let mut first: Option<(Vec<Fr>, ark_groth16::Proof<Bn254>)> = None;
    for (q, steps) in qs.iter().enumerate() {
        let truth = find_witness(&traj, steps, None).is_some();
        let Some(slot) = wallet.next(&c, &verifier, budget) else {
            eprintln!("query {:>2}: budget spent -> prover refuses (no information released)", q + 1);
            rows.push(format!("{},{},refused,,,,", q + 1, truth));
            continue;
        };
        let cc = circ(steps, slot);
        let public = cc.public_inputs(&h);
        let t = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, cc, &mut rng).unwrap();
        let prove_ms = ms(t);
        let t = Instant::now();
        let valid = Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
        let fresh = log.accept(&verifier, public.last().unwrap());
        let verify_ms = ms(t);
        assert!(valid && fresh);
        eprintln!("query {:>2}: answer {:<5} slot {slot}  proof valid, nullifier new -> accepted  (prove {prove_ms:.0} ms)", q + 1, truth);
        rows.push(format!("{},{},{},{},{:.0},{:.2},accepted", q + 1, truth, truth, slot, prove_ms, verify_ms));
        if first.is_none() {
            first = Some((public, proof));
        }
    }
    let (public, proof) = first.unwrap();
    let valid = Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
    let fresh = log.accept(&verifier, public.last().unwrap());
    eprintln!("replay of the first proof: proof valid = {valid}, nullifier new = {fresh} -> {}",
        if fresh { "ACCEPTED (bug)" } else { "rejected" });
    assert!(!fresh);
    rows.push(format!("replay,,,0,,,{}", if fresh { "accepted" } else { "rejected" }));

    let mut f = File::create("results/n5_budget_protocol.csv").unwrap();
    writeln!(f, "query,truth,answer,slot,prove_ms,verify_ms,verifier_decision").unwrap();
    for r in rows {
        writeln!(f, "{r}").unwrap();
    }

    // Scan (either outcome) versus selector (true outcome only) policy cost.
    eprintln!("\npolicy part only (2-step with gap): n, selector (proves 'yes' only), scan (proves yes or no)");
    let mut f = File::create("results/n5_scan_cost.csv").unwrap();
    writeln!(f, "n_points,selector_constraints,scan_constraints,budgeted_total").unwrap();
    for nn in [32usize, 64, 128, 256, 512] {
        let tr: Vec<Point> = (0..nn).map(|i| Point { x: 5, y: 5, t: i as u64 }).collect();
        let steps = vec![Step { zone: BoxZone { xmin: 0, xmax: 9, ymin: 0, ymax: 9 }, max_gap: None },
            Step { zone: BoxZone { xmin: 0, xmax: 9, ymin: 0, ymax: 9 }, max_gap: Some(3) }];
        let (scan, ok) = count::<Fr, _>(ScanPolicyCircuit { traj: tr, steps, avoid: None, outcome: true });
        assert!(ok);
        let sel = ours_constraints(nn, 2, 1);
        let total = if nn == n { m.to_string() } else { String::new() };
        eprintln!("  n = {nn:>4}: selector {sel:>7}, scan {scan:>7} ({:.1}x)", scan as f64 / sel as f64);
        writeln!(f, "{nn},{sel},{scan},{total}").unwrap();
    }
    eprintln!("wrote results/n5_budget_protocol.csv and results/n5_scan_cost.csv");
}
