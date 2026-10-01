//! Step 2 (provisioning): one-time key generation cost and epoch subtrees
//! versus a monolithic device tree.
//!
//! Usage: cargo run --release --manifest-path rust/zkmob-circuits/Cargo.toml --bin keygen_bench -- [--epoch-depth 10]

use std::fs::File;
use std::io::Write;
use std::time::Instant;

use ark_bn254::Fr;
use zkmob_circuits::sig::*;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let depth: usize = args.iter().position(|a| a == "--epoch-depth").map(|i| args[i + 1].parse().unwrap()).unwrap_or(10);
    let h = Hasher::<Fr>::new();
    let reps = 64u64;

    let t = Instant::now();
    for i in 0..reps {
        std::hint::black_box(ots_keygen_poseidon_prf(&h, Fr::from(7u64), i));
    }
    let old = ms(t) / reps as f64;
    let t = Instant::now();
    for i in 0..reps {
        std::hint::black_box(ots_keygen(&h, &[7u8; 32], i));
    }
    let new = ms(t) / reps as f64;

    let m = mldsa_from_seed([1u8; 32]);
    let mut dev = Device::<Fr>::manufacture([2u8; 32], [3u8; 32], depth, &m);
    let mut reg = Registry::new(&h, 20);
    let t = Instant::now();
    let id = reg.enroll(&dev.vk_bytes(), &dev.cert, &mldsa_vk(&m)).unwrap();
    let enroll = ms(t);
    let t = Instant::now();
    let ec = dev.new_epoch(&h);
    let epoch_gen = ms(t);
    let t = Instant::now();
    reg.register_epoch(&h, id, &ec).unwrap();
    let register = ms(t);

    let leaves = 1u64 << depth;
    let flat20_h = old * (1u64 << 20) as f64 / 3.6e6;
    eprintln!("one-time key generation: Poseidon PRF {old:.1} ms -> SHA-512 PRF {new:.1} ms per key ({:.0}% less)", 100.0 * (1.0 - new / old));
    eprintln!("monolithic 2^20 device tree (previous design): {flat20_h:.1} h of key generation before first use");
    eprintln!("epoch subtree 2^{depth} = {leaves} traces: {:.1} s to generate, then enroll {enroll:.2} ms (once) + register epoch {register:.2} ms",
        epoch_gen / 1e3);
    eprintln!("per trace amortised: {:.1} ms key generation + {:.3} ms registry work", epoch_gen / leaves as f64, register / leaves as f64);
    eprintln!("circuit Merkle levels: epoch {depth} + registry 20 = {} (previous: device 20 + registry 16 = 36)", depth + 20);

    let mut f = File::create("results/keygen_bench.csv").unwrap();
    writeln!(f, "ots_keygen_ms_poseidon_prf,ots_keygen_ms_sha512_prf,flat_2e20_tree_hours,epoch_depth,epoch_leaves,epoch_gen_s,enroll_ms,register_epoch_ms,epoch_cert_bytes,device_cert_bytes,circuit_merkle_levels").unwrap();
    writeln!(f, "{old:.2},{new:.2},{flat20_h:.2},{depth},{leaves},{:.2},{enroll:.3},{register:.3},{},{},{}",
        epoch_gen / 1e3, ec.sig.len(), dev.cert.len(), depth + 20).unwrap();
    eprintln!("wrote results/keygen_bench.csv");
}
