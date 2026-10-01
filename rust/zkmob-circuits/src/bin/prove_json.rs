//! Prove one policy on one real trace exported by the Python side
//! (roadmap step 4: Python -> JSON -> Rust).
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin prove_json -- \
//!       --trace work/trace.json --policy work/policy.json [--commit off|binding|hiding] [--no-prove]
//!
//! Prints one JSON object. With `--commit hiding` (default) a fresh 128-bit
//! blinding value is read from /dev/urandom, as the device would do.

use std::io::Read;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde_json::json;
use zkmob_circuits::commit::Commit;
use zkmob_circuits::io::{to_points, validate, PolicyJson, TraceJson};
use zkmob_circuits::ordered::OrderedPolicyCircuit;
use zkmob_circuits::synth::count;
use zkmob_circuits::types::find_witness;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).map(|i| args[i + 1].clone())
}

fn urandom_u128() -> u128 {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("read /dev/urandom");
    u128::from_le_bytes(b)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trace: TraceJson = serde_json::from_str(&std::fs::read_to_string(arg(&args, "--trace").expect("--trace")).unwrap())
        .expect("trace JSON");
    let policy: PolicyJson = serde_json::from_str(&std::fs::read_to_string(arg(&args, "--policy").expect("--policy")).unwrap())
        .expect("policy JSON");
    let mode = match arg(&args, "--commit").as_deref().unwrap_or("hiding") {
        "off" => Commit::Off,
        "binding" => Commit::Binding,
        "hiding" => Commit::Hiding(urandom_u128()),
        m => panic!("unknown --commit {m}"),
    };
    let prove = !args.iter().any(|a| a == "--no-prove");

    let traj = to_points(&trace.points);
    validate(&traj).expect("trace violates circuit assumptions");
    let (steps, avoid) = (policy.steps(), policy.avoid());
    let Some(wit) = find_witness(&traj, &steps, avoid.as_ref()) else {
        println!("{}", json!({"holds": false, "n_points": traj.len(),
            "note": "policy does not hold on this trace; an honest prover cannot produce a proof"}));
        return;
    };
    let c = OrderedPolicyCircuit { traj: traj.clone(), steps, avoid, witness: Some(wit.clone()), commit: mode };
    let (m, ok) = count::<Fr, _>(c.clone());
    let public = c.public_inputs::<Fr>();
    let commitment = if mode.is_on() {
        Some(hex(&public.last().unwrap().into_bigint().to_bytes_be()))
    } else {
        None
    };
    let mut out = json!({
        "holds": true, "n_points": traj.len(), "witness_indices": wit, "constraints": m,
        "satisfied": ok, "commit": format!("{:?}", mode).split('(').next().unwrap().to_lowercase(),
        "commitment": commitment,
    });
    if prove {
        let mut rng = StdRng::seed_from_u64(urandom_u128() as u64);
        let t = Instant::now();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
        let setup_ms = t.elapsed().as_millis();
        let t = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
        let prove_ms = t.elapsed().as_millis();
        let t = Instant::now();
        let verified = Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
        let verify_ms = t.elapsed().as_millis();
        out["setup_ms"] = json!(setup_ms);
        out["prove_ms"] = json!(prove_ms);
        out["verify_ms"] = json!(verify_ms);
        out["verified"] = json!(verified);
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
