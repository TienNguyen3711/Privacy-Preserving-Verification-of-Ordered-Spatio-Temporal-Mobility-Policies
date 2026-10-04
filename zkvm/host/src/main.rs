use std::io::Write;
use std::time::Instant;

use host::*;
use methods::{ZKMOB_GUEST_ELF, ZKMOB_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts};
use zkmob_core::{check, Journal, Statement};

fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env()).init();
    assert!(std::env::var("RISC0_DEV_MODE").is_err(), "unset RISC0_DEV_MODE: dev mode makes fake receipts");
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str, d: &str| args.iter().position(|a| a == k).map(|i| args[i + 1].clone()).unwrap_or(d.to_string());
    let n: usize = arg("--n", "128").parse().unwrap();
    let traces = arg("--traces", "../work/n1_geolife.jsonl");
    let out = arg("--out", "../results/zkvm_budget.csv");

    let traj = load_trace(&traces, n);
    let t = Instant::now();
    let signed = if args.iter().any(|a| a == "--fixture") {
        eprintln!("WARNING: deterministic benchmark fixture; no confidentiality claim");
        setup_fixture(traj.clone(), 10, 20, 1000)
    } else {
        setup_randomized_local(traj.clone(), 10, 20, 1000).expect("OS entropy")
    };
    eprintln!("device epoch (2^10 Lamport-SHA256 keys) + registry: {:.1} s", t.elapsed().as_secs_f64());

    let verifier = sha(&[b"verifier/insurer-A"]);
    // --reverse proves the "no"-candidate statement first, so repeated timing
    // runs can alternate the order and avoid confounding outcome with position.
    let mut order = [(0.2, 0.6, 1.5, 0u32), (0.2, 0.6, 0.5, 1)];
    if args.iter().any(|a| a == "--reverse") { order.reverse(); }
    let statements: Vec<(Statement, u32)> = order
        .iter()
        .map(|&(a, b, f, slot)| {
            let pol = policy_between(&traj, (a * n as f64) as usize, (b * n as f64) as usize, f);
            (Statement { policy: pol, reg_root: signed.reg_root, verifier, budget: 6 }, slot)
        })
        .collect();

    let file_exists = std::path::Path::new(&out).exists();
    let mut csv = std::fs::OpenOptions::new().create(true).append(true).open(&out).unwrap();
    if !file_exists {
        writeln!(csv, "n_points,outcome,total_cycles,user_cycles,segments,prove_s,verify_ms,receipt_bytes,journal_bytes").unwrap();
    }
    for (st, slot) in statements {
        let w = signed.witness(slot);
        let expected = check::<H>(&st, &w); // native run of the same relation
        let env = ExecutorEnv::builder().write(&st).unwrap().write_slice(&[w.to_bytes().len() as u32]).write_slice(&w.to_bytes()).build().unwrap();
        let t = Instant::now();
        let info = default_prover().prove_with_opts(env, ZKMOB_GUEST_ELF, &ProverOpts::succinct()).unwrap();
        let prove_s = t.elapsed().as_secs_f64();
        let receipt = info.receipt;
        assert!(matches!(receipt.inner, InnerReceipt::Succinct(_)), "expected a succinct STARK receipt");
        let t = Instant::now();
        receipt.verify(ZKMOB_GUEST_ID).expect("receipt verifies");
        let verify_ms = t.elapsed().as_secs_f64() * 1e3;
        let journal: Journal = receipt.journal.decode().unwrap();
        assert_eq!(journal, expected, "guest and native relation agree");
        let bytes = bincode::serialize(&receipt).unwrap().len();
        eprintln!("n = {n}: outcome {:<5} | cycles {} (user {}), {} segment(s) | prove {prove_s:.1} s | verify {verify_ms:.1} ms | receipt {bytes} B",
            journal.outcome, info.stats.total_cycles, info.stats.user_cycles, info.stats.segments);
        writeln!(csv, "{n},{},{},{},{},{prove_s:.2},{verify_ms:.2},{bytes},{}", journal.outcome, info.stats.total_cycles,
            info.stats.user_cycles, info.stats.segments, receipt.journal.bytes.len()).unwrap();
    }
}
