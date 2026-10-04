//! Cycle profile of the guest (executor only, no proving): how many cycles
//! go to reading the input versus checking the relation.
//! Usage (from code/zkvm): cargo run --release -p host --bin profile -- [--n 128]

use host::*;
use methods::ZKMOB_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use zkmob_core::Statement;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.iter().position(|a| a == "--n").map(|i| args[i + 1].parse().unwrap()).unwrap_or(128);
    let traj = load_trace("../work/n1_geolife.jsonl", n);
    let signed = setup_fixture(traj.clone(), 10, 20, 1000);
    let st = Statement { policy: policy_between(&traj, n / 5, 3 * n / 5, 1.5), reg_root: signed.reg_root, verifier: sha(&[b"v"]), budget: 6, period: 0 };
    let env = ExecutorEnv::builder().write(&st).unwrap().write_slice(&[signed.witness(0).to_bytes().len() as u32]).write_slice(&signed.witness(0).to_bytes()).build().unwrap();
    let s = default_executor().execute(env, ZKMOB_GUEST_ELF).unwrap();
    eprintln!("n = {n}: total {} cycles ({} segments)", s.cycles(), s.segments.len());
}
