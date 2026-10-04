//! Hidden-signature microbenchmark (see `sigbench.rs`). Prints one CSV row
//! per variant; run each variant in its own process to measure peak memory:
//!   cargo run --release --bin sig_bench -- --header
//!   cargo run --release --bin sig_bench -- --variant lamport_t17
//! Variants: lamport_t3 lamport_t9 lamport_t17 wots_w4_t3 wots_w4_t17 wots_w4x_t3 wots_w16_t3 wots_w16_t17
//! (x = tweaked, WOTS+-style address-bound chains)

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use zkmob_circuits::sigbench::*;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn parse(name: &str) -> Variant {
    let (s, t) = name.rsplit_once("_t").expect("variant name");
    let comp_rate = t.parse::<usize>().unwrap() - 1;
    let tweaked = s.ends_with('x');
    let scheme = match s.trim_end_matches('x') {
        "lamport" => Scheme::Lamport,
        "wots_w4" => Scheme::Wots { log_w: 2 },
        "wots_w16" => Scheme::Wots { log_w: 4 },
        _ => panic!("unknown scheme {s}"),
    };
    Variant { scheme, comp_rate, tweaked }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--header") {
        println!("variant,constraints,matrix_nonzeros,witness_vars,sig_elems,sig_bytes,keygen_ms,sign_ms,native_verify_ms,synth_ms,setup_ms,prove_ms,verify_ms");
        return;
    }
    let name = args.iter().position(|a| a == "--variant").map(|i| args[i + 1].clone()).expect("--variant");
    let p = Params::<Fr>::new(parse(&name));
    let seed = [9u8; 32];
    let m = Fr::from(0x1234_5678_9abc_def0_u64) * Fr::from(0xfeed_face_u64);

    let reps = 8;
    let t = Instant::now();
    let mut pk = Fr::from(0u64);
    for leaf in 0..reps {
        pk = p.keygen(&seed, leaf);
    }
    let keygen = ms(t) / reps as f64;
    let leaf = reps - 1;
    let t = Instant::now();
    let sig = p.sign(&seed, leaf, &m);
    let sign = ms(t);
    let t = Instant::now();
    assert_eq!(p.verify(&m, &sig), pk);
    let nverify = ms(t);

    let t = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    SigCircuit { p: &p, m, sig: sig.clone(), pk }.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let synth = ms(t);
    assert!(cs.is_satisfied().unwrap());
    let (cons, wit) = (cs.num_constraints(), cs.num_witness_variables());
    let mat = cs.to_matrices().unwrap();
    let nnz = mat.a_num_non_zero + mat.b_num_non_zero + mat.c_num_non_zero;

    let mut rng = StdRng::seed_from_u64(1);
    let t = Instant::now();
    let (pkey, vk) = Groth16::<Bn254>::circuit_specific_setup(SigCircuit { p: &p, m, sig: sig.clone(), pk }, &mut rng).unwrap();
    let setup = ms(t);
    // median of 3 proofs
    let mut times = Vec::new();
    let mut proof = None;
    for _ in 0..3 {
        let t = Instant::now();
        proof = Some(Groth16::<Bn254>::prove(&pkey, SigCircuit { p: &p, m, sig: sig.clone(), pk }, &mut rng).unwrap());
        times.push(ms(t));
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (prove, proof) = (times[1], proof.unwrap());
    let t = Instant::now();
    assert!(Groth16::<Bn254>::verify(&vk, &[pk], &proof).unwrap());
    let verify = ms(t);
    println!("{name},{cons},{nnz},{wit},{},{},{keygen:.2},{sign:.2},{nverify:.2},{synth:.0},{setup:.0},{prove:.0},{verify:.2}",
        sig.len(), sig.len() * 32);
}
