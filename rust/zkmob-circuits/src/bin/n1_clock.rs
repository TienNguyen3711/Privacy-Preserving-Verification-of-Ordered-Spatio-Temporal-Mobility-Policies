//! BL-clockDFA on the C1 workloads (review item 7): the exact-time automaton
//! baseline, priced and checked on every policy of an `n1_export` (or
//! `n1_grid_export`) batch.
//!
//! For every item: the BL-clockDFA answer must equal the Rust reference
//! semantics (`find_witness`) and the Python `evaluate` result carried in the
//! batch; the cost comes from the closed form `clock_constraints`, and the
//! first `--check N` items are also synthesized to confirm the count and
//! that the honest outcome satisfies the circuit. Costs depend only on n and
//! the policy shape, so no width column: the automaton has no bucket width.
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin n1_clock -- \
//!       --in work/n1_geolife.jsonl --out results/n1_clock_geolife.csv [--check 50]

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use ark_bn254::Fr;
use zkmob_circuits::automaton::{clock_constraints, clock_dfa_accepts, ClockDfaCircuit};
use zkmob_circuits::io::{to_points, validate, BatchItem};
use zkmob_circuits::synth::count;
use zkmob_circuits::types::find_witness;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).map(|i| args[i + 1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = arg(&args, "--in").expect("--in batch.jsonl");
    let out = arg(&args, "--out").expect("--out results.csv");
    let check: usize = arg(&args, "--check").map(|s| s.parse().unwrap()).unwrap_or(50);

    let mut f = File::create(&out).expect("create csv");
    writeln!(f, "id,dataset,n_points,truth,clock_answer,clock_constraints").unwrap();
    let (mut items, mut checked) = (0usize, 0usize);
    for line in BufReader::new(File::open(&input).expect("open batch")).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let it: BatchItem = serde_json::from_str(&line).expect("batch line");
        let traj = to_points(&it.points);
        validate(&traj).unwrap_or_else(|e| panic!("{}: {e}", it.id));
        let steps = it.policy.steps();
        let avoid = it.policy.avoid();
        let truth = find_witness(&traj, &steps, avoid.as_ref()).is_some();
        assert_eq!(truth, it.expected, "{}: Rust and Python semantics disagree", it.id);
        let answer = clock_dfa_accepts(&traj, &steps, avoid.as_ref());
        assert_eq!(answer, truth, "{}: BL-clockDFA disagrees with the reference semantics", it.id);
        let gapped = steps.iter().filter(|s| s.max_gap.is_some()).count();
        let cost = clock_constraints(traj.len(), steps.len(), gapped, avoid.is_some());
        if checked < check {
            let (m, ok) = count::<Fr, _>(ClockDfaCircuit { traj: traj.clone(), steps: steps.clone(), avoid, outcome: truth });
            assert_eq!(m, cost, "{}: clock cost formula", it.id);
            assert!(ok, "{}: honest outcome must satisfy the circuit", it.id);
            checked += 1;
        }
        writeln!(f, "{},{},{},{},{},{}", it.id, it.dataset, traj.len(), truth, answer, cost).unwrap();
        items += 1;
    }
    eprintln!("{items} items, all BL-clockDFA answers equal the reference; {checked} circuits synthesized; wrote {out}");
}
