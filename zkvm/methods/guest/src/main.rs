//! zkVM guest: checks the budgeted, unlinkable policy relation
//! (`zkmob_core::check`) and publishes only the journal (policy, outcome,
//! registry root, verifier, budget, period, nullifier). Any invalid witness makes
//! the guest panic, so no receipt can be produced for it.

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use zkmob_core::{check, Digest, Hasher, Statement, Witness};

/// SHA-256 via the zkVM accelerator.
struct R0Sha;

impl Hasher for R0Sha {
    fn hash(data: &[u8]) -> Digest {
        Impl::hash_bytes(data).as_bytes().try_into().unwrap()
    }
}

fn main() {
    let c0 = env::cycle_count();
    let statement: Statement = env::read();
    // witness as compact bytes: length (u32 words), then the bytes
    let mut len = [0u32; 1];
    env::read_slice(&mut len);
    let mut buf = vec![0u8; len[0] as usize];
    env::read_slice(&mut buf);
    let witness = Witness::from_bytes(&buf);
    let c1 = env::cycle_count();
    let journal = check::<R0Sha>(&statement, &witness);
    let c2 = env::cycle_count();
    env::commit(&journal);
    eprintln!("guest cycles: read input {}, check relation {}", c1 - c0, c2 - c1);
}
