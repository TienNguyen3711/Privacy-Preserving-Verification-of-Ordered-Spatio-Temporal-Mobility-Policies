//! Plonky3 (zero-knowledge, hash-based STARK) cost of the relation's two
//! components on real GeoLife traces:
//!   1. policy scan (`ScanAir`), yes and no outcomes;
//!   2. the hash workload of the unlinkable, budgeted relation as Poseidon2
//!      permutations (width 16, BabyBear): commitment ceil((3n + 4) / 8),
//!      Lamport on a 248-bit digest (248 leaf hashes + 496 absorptions of
//!      8-element digests), 30 Merkle levels (epoch 10 + registry 20), and
//!      the nullifier (3).
//! The two are proven SEPARATELY here; linking them (the scan's fixes are
//! the committed ones) needs a cross-table lookup, which is not implemented,
//! so "sum" is an estimate of the composed proof, not a measured one.
//!
//! Usage (from code/stark): cargo run --release --bin stark_bench -- [--traces ../work/n1_geolife.jsonl]

use std::io::{BufRead, Write};
use std::time::Instant;

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
    GenericPoseidon2LinearLayersBabyBear,
};
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_uni_stark::{prove, verify};
use rand::SeedableRng;
use zkmob_core::{scan_eval, BoxZone, Point, Policy, Step};
use zkmob_stark::*;

type P2Air = VectorizedPoseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    16,
    BABYBEAR_S_BOX_DEGREE,
    1,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    1,
>;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn load(path: &str, n: usize) -> Vec<Point> {
    let f = std::io::BufReader::new(std::fs::File::open(path).expect("open traces (run zkmob.n1_export first)"));
    for line in f.lines() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let pts = v["points"].as_array().unwrap();
        if pts.len() >= n {
            return pts[..n].iter().map(|p| Point { x: p[0].as_u64().unwrap() as u32, y: p[1].as_u64().unwrap() as u32, t: p[2].as_u64().unwrap() as u32 }).collect();
        }
    }
    panic!("no trace with >= {n} points");
}

fn policy(traj: &[Point], f: f64) -> Policy {
    let n = traj.len();
    let (i, j) = (n / 5, 3 * n / 5);
    let around = |p: &Point| BoxZone { xmin: p.x - 100, xmax: p.x + 100, ymin: p.y - 100, ymax: p.y + 100 };
    let gap = ((traj[j].t - traj[i].t) as f64 * f) as u32;
    Policy { steps: vec![Step { zone: around(&traj[i]), max_gap: None }, Step { zone: around(&traj[j]), max_gap: Some(gap) }], avoid: None }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let traces = args.iter().position(|a| a == "--traces").map(|i| args[i + 1].clone()).unwrap_or("../work/n1_geolife.jsonl".into());
    let config = zk_config();
    let mut csv = std::fs::File::create("../results/stark_bench.csv").unwrap();
    writeln!(csv, "component,n_points,outcome,rows,width,prove_ms,verify_ms,proof_bytes").unwrap();
    let reps = 3;

    let mut scan_ms = std::collections::HashMap::new();
    for n in [128usize, 256, 512, 1024] {
        let traj = load(&traces, n);
        for f in [1.5, 0.5] {
            let pol = policy(&traj, f);
            let outcome = scan_eval(&traj, &pol);
            let air = ScanAir { layout: Layout { k: 2, avoid: false } };
            let pis = public_values(&pol, outcome);
            let trace = generate_trace(&traj, &pol);
            let (rows, width) = (trace.values.len() / air.layout.width(), air.layout.width());
            let (mut pt, mut vt, mut bytes) = (Vec::new(), Vec::new(), 0);
            for _ in 0..reps {
                let t = Instant::now();
                let proof = prove(&config, &air, trace.clone(), &pis).unwrap();
                pt.push(ms(t));
                let t = Instant::now();
                verify(&config, &air, &proof, &pis).unwrap();
                vt.push(ms(t));
                bytes = postcard::to_allocvec(&proof).unwrap().len();
            }
            let (p, v) = (median(pt), median(vt));
            scan_ms.insert((n, outcome), (p, v, bytes));
            eprintln!("scan     n = {n:>4} outcome {outcome:<5}: {rows} x {width}, prove {p:>6.0} ms, verify {v:>5.1} ms, proof {bytes} B");
            writeln!(csv, "scan,{n},{outcome},{rows},{width},{p:.1},{v:.2},{bytes}").unwrap();
        }
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let air = P2Air::new(RoundConstants::from_rng(&mut rng));
    for n in [128usize, 256, 512, 1024] {
        let perms = (3 * n + 4).div_ceil(8) + 248 + 496 + 30 + 3;
        let rows = perms.next_power_of_two().max(MIN_ROWS);
        let trace = air.generate_vectorized_trace_rows(rows, 2);
        let width = trace.width;
        let (mut pt, mut vt, mut bytes) = (Vec::new(), Vec::new(), 0);
        for _ in 0..reps {
            let t = Instant::now();
            let proof = prove(&config, &air, trace.clone(), &[]).unwrap();
            pt.push(ms(t));
            let t = Instant::now();
            verify(&config, &air, &proof, &[]).unwrap();
            vt.push(ms(t));
            bytes = postcard::to_allocvec(&proof).unwrap().len();
        }
        let (p, v) = (median(pt), median(vt));
        eprintln!("poseidon2 n = {n:>4}: {perms} permutations -> {rows} x {width}, prove {p:>6.0} ms, verify {v:>5.1} ms, proof {bytes} B");
        writeln!(csv, "poseidon2_workload,{n},,{rows},{width},{p:.1},{v:.2},{bytes}").unwrap();
        let (sp, sv, sb) = scan_ms[&(n, true)];
        eprintln!("  sum (scan + hashes, unlinked): prove {:.0} ms, verify {:.1} ms, {} B", sp + p, sv + v, sb + bytes);
        writeln!(csv, "sum_unlinked_estimate,{n},,,,{:.1},{:.2},{}", sp + p, sv + v, sb + bytes).unwrap();
    }
    eprintln!("wrote ../results/stark_bench.csv");
}
