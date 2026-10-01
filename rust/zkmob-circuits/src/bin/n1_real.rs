//! Claim N1 on real traces: exactness and cost of our design versus B3
//! (discretise + DFA) across bucket widths.
//!
//! Input: a JSONL batch from `python -m zkmob.n1_export` (two-step policies
//! "A, then B within max_gap"). For every item and bucket width w:
//!   * truth    = exact semantics (`find_witness`), cross-checked against
//!                the Python `evaluate` result carried in the batch;
//!   * B3       = native DFA on the carry-forward resampled trace (exactly
//!                what the circuit computes, see `automaton_matches_native_dfa`)
//!                and on the "any-fix" discretisation (most favourable to
//!                B3), with the constraint count from the closed form
//!                `b3_constraints` (a lower bound for any-fix);
//!   * ours     = closed form `ours_constraints`; for the first
//!                `--check N` items the circuit is also synthesized to
//!                confirm the count and that the honest witness satisfies it.
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin n1_real -- \
//!       --in work/n1_geolife.jsonl --out results/n1_real_geolife.csv [--check 50]

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use ark_bn254::Fr;
use zkmob_circuits::automaton::{b3_constraints, bucket_flags_any, dfa_accepts, dfa_accepts_flags, resample};
use zkmob_circuits::commit::Commit;
use zkmob_circuits::io::{to_points, validate, BatchItem};
use zkmob_circuits::ordered::{ours_constraints, OrderedPolicyCircuit};
use zkmob_circuits::synth::count;
use zkmob_circuits::types::find_witness;

const WIDTHS: [u64; 9] = [600, 300, 180, 120, 60, 30, 15, 10, 5];

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).map(|i| args[i + 1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = arg(&args, "--in").expect("--in batch.jsonl");
    let out = arg(&args, "--out").expect("--out results.csv");
    let check: usize = arg(&args, "--check").map(|s| s.parse().unwrap()).unwrap_or(50);

    let mut f = File::create(&out).expect("create csv");
    writeln!(f, "id,dataset,kind,zone_half_m,gap_factor,n_points,duration_s,max_gap_s,truth,ours_constraints,\
bucket_s,b3_steps,b3_states,b3_constraints,b3_answer,b3_any_answer").unwrap();

    let (mut items, mut mismatches, mut checked) = (0usize, 0usize, 0usize);
    for line in BufReader::new(File::open(&input).expect("open batch")).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let it: BatchItem = serde_json::from_str(&line).expect("batch line");
        let traj = to_points(&it.points);
        validate(&traj).unwrap_or_else(|e| panic!("{}: {e}", it.id));
        let steps = it.policy.steps();
        assert!(steps.len() == 2 && it.policy.avoid.is_none(), "{}: n1_real expects 'A then B within gap'", it.id);
        let gap = steps[1].max_gap.expect("second step needs max_gap");

        let wit = find_witness(&traj, &steps, None);
        let truth = wit.is_some();
        if truth != it.expected {
            mismatches += 1;
            eprintln!("MISMATCH {}: rust={truth} python={}", it.id, it.expected);
        }
        let n = traj.len();
        let ours = ours_constraints(n, 2, 1);
        if checked < check {
            if let Some(w) = wit.clone() {
                let c = OrderedPolicyCircuit { traj: traj.clone(), steps: steps.clone(), avoid: None, witness: Some(w), commit: Commit::Off };
                let (m, ok) = count::<Fr, _>(c);
                assert_eq!(m, ours, "{}: cost formula", it.id);
                assert!(ok, "{}: honest witness must satisfy the circuit", it.id);
                checked += 1;
            }
        }

        let meta = |k: &str| it.meta.get(k).map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
        let horizon = traj.last().unwrap().t + 1;
        for w in WIDTHS {
            let sym = resample(&traj, w, horizon);
            let k = gap.div_ceil(w).max(1) as usize;
            let b3 = dfa_accepts(&sym, &steps[0].zone, &steps[1].zone, k);
            let b3_any = dfa_accepts_flags(&bucket_flags_any(&traj, &steps[0].zone, &steps[1].zone, w, horizon), k);
            writeln!(f, "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}", it.id, it.dataset, meta("kind"), meta("zone_half_m"),
                meta("gap_factor"), n, horizon - 1, gap, truth, ours, w, sym.len(), k + 2, b3_constraints(sym.len(), k), b3, b3_any).unwrap();
        }
        items += 1;
        if items % 200 == 0 {
            eprintln!("{items} items...");
        }
    }
    eprintln!("{items} items, {mismatches} rust/python mismatches, {checked} circuits synthesized and checked; wrote {out}");
    assert_eq!(mismatches, 0, "Rust and Python semantics disagree");
}
