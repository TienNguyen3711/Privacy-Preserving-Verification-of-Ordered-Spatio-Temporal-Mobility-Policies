//! Claim N4 (roadmap step 6): linkability and cost of four ways to bind a
//! policy proof to a device-signed trace.
//!
//! * B2-ECDSA        C = Poseidon(T) public; device signs C with ECDSA P-256
//! * B2-MLDSA        C = Poseidon(T) public; device signs C with ML-DSA-65
//! * B2-MLDSA-hiding C = Poseidon(r || T) public; ML-DSA-65
//! * Unlinkable      C, the Lamport-Poseidon signature and the epoch root are
//!                   witnesses; public = policy || registry root (sig.rs)
//!
//! D devices each record K real trips and prove P true policies per trip.
//! A linking verifier compares every pair of presentations and links them
//! if they share any value that is not common to all presentations (C, a
//! signature, a device key; a registry root shared by everyone carries no
//! information). We report link rates for same-trip, same-device and
//! different-device pairs, plus sizes and timings.
//!
//! Usage (from the repo root):
//!   cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin n4_link -- \
//!       [--traces work/n1_geolife.jsonl] [--n 128] [--devices 4] [--trips 3] [--policies 3] \
//!       [--dev-depth 6] [--reg-depth 16] [--out results/n4_linkability.csv]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use p256::ecdsa::signature::{Signer, Verifier};
use zkmob_circuits::commit::{commit_native_hiding, poseidon_config, Commit};
use zkmob_circuits::io::{to_points, BatchItem};
use zkmob_circuits::ordered::{ours_constraints, OrderedPolicyCircuit};
use zkmob_circuits::sig::*;
use zkmob_circuits::synth::count;
use zkmob_circuits::types::{find_witness, BoxZone, Point, Step};
use zkmob_circuits::unlinkable::UnlinkableCircuit;

fn arg<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter().position(|a| a == name).and_then(|i| args[i + 1].parse().ok()).unwrap_or(default)
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// One proof as the verifier receives it.
struct Presentation {
    device: usize,
    trip: usize,
    /// Values beyond the policy statement that the verifier sees.
    ids: Vec<Vec<u8>>,
    bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
}

fn load_trips(path: &str, n: usize, want: usize) -> Vec<Vec<Point>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in BufReader::new(File::open(path).expect("open traces (run zkmob.n1_export first)")).lines() {
        let it: BatchItem = serde_json::from_str(&line.unwrap()).unwrap();
        let trip = it.id.split('#').next().unwrap().to_string();
        if it.points.len() >= n && seen.insert(trip) {
            out.push(to_points(&it.points[..n]));
            if out.len() == want {
                break;
            }
        }
    }
    assert_eq!(out.len(), want, "not enough trips with >= {n} points");
    out
}

/// P policies that hold on `traj`: A around fix i, B around fix j > i,
/// within the observed gap + 60 s. Same shape for every trip.
fn policies(traj: &[Point], p: usize, rng: &mut StdRng) -> Vec<Vec<Step>> {
    let around = |q: &Point| BoxZone { xmin: q.x.saturating_sub(100), xmax: q.x + 100, ymin: q.y.saturating_sub(100), ymax: q.y + 100 };
    (0..p)
        .map(|_| {
            let i = rng.gen_range(0..traj.len() - 1);
            let j = rng.gen_range(i + 1..traj.len());
            vec![Step { zone: around(&traj[i]), max_gap: None }, Step { zone: around(&traj[j]), max_gap: Some(traj[j].t - traj[i].t + 60) }]
        })
        .collect()
}

fn proof_bytes(p: &ark_groth16::Proof<Bn254>) -> usize {
    p.compressed_size()
}

fn fb(x: &Fr) -> Vec<u8> {
    field_bytes(x)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let traces: String = arg(&args, "--traces", "work/n1_geolife.jsonl".to_string());
    let n: usize = arg(&args, "--n", 128);
    let d_n: usize = arg(&args, "--devices", 4);
    let k_n: usize = arg(&args, "--trips", 3);
    let p_n: usize = arg(&args, "--policies", 3);
    let dev_depth: usize = arg(&args, "--dev-depth", 6);
    let reg_depth: usize = arg(&args, "--reg-depth", 16);
    let out: String = arg(&args, "--out", "results/n4_linkability.csv".to_string());

    let mut rng = StdRng::seed_from_u64(2026);
    let trips = load_trips(&traces, n, d_n * k_n);
    let pols: Vec<Vec<Vec<Step>>> = trips.iter().map(|t| policies(t, p_n, &mut rng)).collect();
    let trip_of = |d: usize, k: usize| d * k_n + k;
    eprintln!("{} devices x {} trips x {} policies, n = {} fixes per trip", d_n, k_n, p_n, n);

    // ---------------- keys ----------------
    let h = Hasher::<Fr>::new();
    let ecdsa: Vec<p256::ecdsa::SigningKey> = (0..d_n)
        .map(|d| p256::ecdsa::SigningKey::from_slice(&[d as u8 + 1; 32]).unwrap())
        .collect();
    let mldsa: Vec<MlDsaSk> = (0..d_n).map(|d| mldsa_from_seed([d as u8 + 101; 32])).collect();
    let manufacturer = mldsa_from_seed([200u8; 32]);
    let mvk = mldsa_vk(&manufacturer);
    let mut devices: Vec<Device<Fr>> = (0..d_n)
        .map(|d| Device::manufacture([d as u8 + 50; 32], [d as u8 + 150; 32], dev_depth, &manufacturer))
        .collect();
    let t = Instant::now();
    let epochs: Vec<EpochCert<Fr>> = devices.iter_mut().map(|dv| dv.new_epoch(&h)).collect();
    let keygen_ms_per_trace = ms(t) / (d_n as f64 * (1u64 << dev_depth) as f64);
    let mut registry = Registry::new(&h, reg_depth);
    let mut reg_idx = Vec::new();
    let mut reg_verify = Vec::new();
    let cert_len = devices[0].cert.len() + epochs[0].sig.len();
    for (dv, ec) in devices.iter().zip(&epochs) {
        let t = Instant::now();
        let id = registry.enroll(&dv.vk_bytes(), &dv.cert, &mvk).unwrap();
        reg_idx.push(registry.register_epoch(&h, id, ec).unwrap());
        reg_verify.push(ms(t));
    }
    eprintln!("epoch keys: {:.1} ms per one-time key; epoch depth {dev_depth}, registry depth {reg_depth}", keygen_ms_per_trace);

    let mut csv = File::create(&out).expect("create csv");
    writeln!(csv, "design,signature,n_points,constraints,setup_ms,prove_ms_median,verify_ms_median,device_sign_ms,\
presentation_bytes,link_same_trip,link_same_device,link_diff_device,pairs_same_trip,pairs_same_device,pairs_diff_device").unwrap();

    // ---------------- B2 variants ----------------
    for (design, scheme, hiding) in [("B2-ECDSA", "ecdsa-p256", false), ("B2-MLDSA", "ml-dsa-65", false), ("B2-MLDSA-hiding", "ml-dsa-65", true)] {
        let mode_for = |trip: usize| if hiding { Commit::Hiding(0xb1d0_0000 + trip as u128) } else { Commit::Binding };
        let circuit = |d: usize, k: usize, p: usize| {
            let tr = trip_of(d, k);
            let steps = pols[tr][p].clone();
            let wit = find_witness(&trips[tr], &steps, None).expect("policy holds");
            OrderedPolicyCircuit { traj: trips[tr].clone(), steps, avoid: None, witness: Some(wit), commit: mode_for(tr) }
        };
        let (m, _) = count::<Fr, _>(circuit(0, 0, 0));
        let t = Instant::now();
        let (pk, vk): (ProvingKey<Bn254>, VerifyingKey<Bn254>) = Groth16::<Bn254>::circuit_specific_setup(circuit(0, 0, 0), &mut rng).unwrap();
        let setup = ms(t);
        let mut pres = Vec::new();
        let mut sign_ms = Vec::new();
        for d in 0..d_n {
            for k in 0..k_n {
                // the device signs C once per trip
                let c: Fr = mode_for(trip_of(d, k)).value(&trips[trip_of(d, k)]).unwrap();
                let msg = fb(&c);
                let t = Instant::now();
                let (sig, dev_pk): (Vec<u8>, Vec<u8>) = if scheme == "ecdsa-p256" {
                    let s: p256::ecdsa::Signature = ecdsa[d].sign(&msg);
                    (s.to_bytes().to_vec(), ecdsa[d].verifying_key().to_sec1_point(true).as_bytes().to_vec())
                } else {
                    (mldsa_sign(&mldsa[d], &msg, SIG_CTX), mldsa_vk(&mldsa[d]).encode().to_vec())
                };
                sign_ms.push(ms(t));
                for p in 0..p_n {
                    let circ = circuit(d, k, p);
                    let public = circ.public_inputs::<Fr>();
                    let t = Instant::now();
                    let proof = Groth16::<Bn254>::prove(&pk, circ, &mut rng).unwrap();
                    let prove_ms = ms(t);
                    // verifier: signature on C (outside), then the proof
                    let t = Instant::now();
                    let sig_ok = if scheme == "ecdsa-p256" {
                        let vkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(&dev_pk).unwrap();
                        vkey.verify(&msg, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).is_ok()
                    } else {
                        mldsa_verify(&mldsa_vk(&mldsa[d]), &msg, SIG_CTX, &sig)
                    };
                    let ok = sig_ok && Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
                    let verify_ms = ms(t);
                    assert!(ok, "{design}: presentation must verify");
                    pres.push(Presentation {
                        device: d, trip: trip_of(d, k), ids: vec![msg.clone(), sig.clone(), dev_pk.clone()],
                        bytes: proof_bytes(&proof) + msg.len() + sig.len() + dev_pk.len(), prove_ms, verify_ms,
                    });
                }
            }
        }
        report(&mut csv, design, scheme, n, m, setup, median(sign_ms), &pres);
    }

    // ---------------- Unlinkable ----------------
    let blind = |tr: usize| 0x5eed_0000_u128 + tr as u128;
    let mut sigs: HashMap<usize, DeviceSig<Fr>> = HashMap::new();
    let mut sign_ms = Vec::new();
    for d in 0..d_n {
        for k in 0..k_n {
            let tr = trip_of(d, k);
            let c = commit_native_hiding(&poseidon_config::<Fr>(), &trips[tr], blind(tr));
            let t = Instant::now();
            let s = devices[d].sign(&h, &c).unwrap();
            sign_ms.push(ms(t));
            assert!(verify_device_sig(&h, epochs[d].root, &c, &s));
            sigs.insert(tr, s);
        }
    }
    let circuit = |d: usize, k: usize, p: usize| {
        let tr = trip_of(d, k);
        let steps = pols[tr][p].clone();
        UnlinkableCircuit {
            traj: trips[tr].clone(), witness: find_witness(&trips[tr], &steps, None), steps, avoid: None,
            blind: blind(tr), sig: sigs[&tr].clone(), reg_index: reg_idx[d], reg_path: registry.path(reg_idx[d]),
            reg_root: registry.root(),
        }
    };
    let (m, ok) = count::<Fr, _>(circuit(0, 0, 0));
    assert!(ok);
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit(0, 0, 0), &mut rng).unwrap();
    let setup = ms(t);
    let mut pres = Vec::new();
    for d in 0..d_n {
        for k in 0..k_n {
            for p in 0..p_n {
                let circ = circuit(d, k, p);
                let public = circ.public_inputs();
                let t = Instant::now();
                let proof = Groth16::<Bn254>::prove(&pk, circ, &mut rng).unwrap();
                let prove_ms = ms(t);
                let t = Instant::now();
                assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap(), "unlinkable proof must verify");
                let verify_ms = ms(t);
                pres.push(Presentation {
                    device: d, trip: trip_of(d, k), ids: vec![fb(public.last().unwrap())],
                    bytes: proof_bytes(&proof), prove_ms, verify_ms,
                });
            }
        }
    }
    report(&mut csv, "Unlinkable", "lamport-poseidon+ml-dsa-cert", n, m, setup, median(sign_ms), &pres);

    // Constraint breakdown of the unlinkable circuit.
    let policy_part = ours_constraints(n, 2, 1);
    let with_commit = {
        let c = circuit(0, 0, 0);
        count::<Fr, _>(OrderedPolicyCircuit { traj: c.traj, steps: c.steps, avoid: None, witness: c.witness, commit: Commit::Hiding(1) }).0
    };
    let per_level = {
        // one more registry level = one more Merkle hash (+ selects, bit)
        let mut reg2 = Registry::new(&h, reg_depth + 1);
        let id = reg2.enroll(&devices[0].vk_bytes(), &devices[0].cert, &mvk).unwrap();
        let idx = reg2.register_epoch(&h, id, &epochs[0]).unwrap();
        let mut c = circuit(0, 0, 0);
        c.reg_index = idx;
        c.reg_path = reg2.path(idx);
        c.reg_root = reg2.root();
        count::<Fr, _>(c).0 - m
    };
    let merkle = per_level * (dev_depth + reg_depth);
    let lamport_part = m - with_commit - merkle;
    eprintln!("\nUnlinkable circuit, n = {n}: {m} constraints = policy {policy_part} + commitment {} + Lamport verify {} \
+ Merkle {} ({} per level x {} levels)", with_commit - policy_part, lamport_part, merkle, per_level, dev_depth + reg_depth);
    eprintln!("registration (enroll + first epoch): 2 ML-DSA-65 signatures, {cert_len} B, verify {:.2} ms", median(reg_verify.clone()));
    eprintln!("epoch key generation: {:.1} ms per one-time key, {:.1} s per 2^{dev_depth}-leaf epoch",
        keygen_ms_per_trace, keygen_ms_per_trace * (1u64 << dev_depth) as f64 / 1e3);
    eprintln!("wrote {out}");
    let mut bf = File::create(out.replace(".csv", "_breakdown.csv")).unwrap();
    writeln!(bf, "n_points,dev_depth,reg_depth,total,policy,commitment,lamport_verify,merkle,merkle_per_level,keygen_ms_per_onetime_key,cert_bytes,cert_verify_ms").unwrap();
    writeln!(bf, "{n},{dev_depth},{reg_depth},{m},{policy_part},{},{lamport_part},{merkle},{per_level},{keygen_ms_per_trace:.2},{cert_len},{:.3}",
        with_commit - policy_part, median(reg_verify.clone())).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn report(csv: &mut File, design: &str, scheme: &str, n: usize, m: usize, setup: f64, sign_ms: f64, pres: &[Presentation]) {
    // values shared by every presentation carry no linking information
    let common: HashSet<&Vec<u8>> = pres[0].ids.iter().filter(|v| pres.iter().all(|p| p.ids.contains(v))).collect();
    let (mut st, mut sd, mut dd) = ((0, 0), (0, 0), (0, 0)); // (linked, pairs)
    for i in 0..pres.len() {
        for j in i + 1..pres.len() {
            let (a, b) = (&pres[i], &pres[j]);
            let linked = a.ids.iter().any(|v| !common.contains(v) && b.ids.contains(v));
            let bucket = if a.trip == b.trip { &mut st } else if a.device == b.device { &mut sd } else { &mut dd };
            bucket.0 += linked as usize;
            bucket.1 += 1;
        }
    }
    let rate = |x: (usize, usize)| x.0 as f64 / x.1.max(1) as f64;
    let prove = median(pres.iter().map(|p| p.prove_ms).collect());
    let verify = median(pres.iter().map(|p| p.verify_ms).collect());
    let bytes = pres[0].bytes;
    eprintln!("{design:>16}: {m:>7} constraints, prove {prove:>7.0} ms, verify {verify:>5.1} ms, {bytes:>5} B; \
linked: same trip {:.0}%, same device {:.0}%, other device {:.0}%", 100.0 * rate(st), 100.0 * rate(sd), 100.0 * rate(dd));
    writeln!(csv, "{design},{scheme},{n},{m},{setup:.0},{prove:.1},{verify:.2},{sign_ms:.3},{bytes},{:.4},{:.4},{:.4},{},{},{}",
        rate(st), rate(sd), rate(dd), st.1, sd.1, dd.1).unwrap();
}
