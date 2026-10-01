//! Host-side device, epoch and registry (SHA-256 instantiation) and helpers
//! to build statements and witnesses for the zkVM guest.

use sha2::{Digest as _, Sha256};
use zkmob_core::*;

pub mod wallet;
pub mod registry;
pub mod vault;
pub mod anchor;

pub struct HostSha;

impl Hasher for HostSha {
    fn hash(data: &[u8]) -> Digest {
        Sha256::digest(data).into()
    }
}

pub type H = HostSha;

pub fn sha(parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Sparse Merkle tree (unused leaves are zero digests).
pub struct Tree {
    pub depth: usize,
    levels: Vec<Vec<Digest>>,
    zero: Vec<Digest>,
}

impl Tree {
    pub fn new(depth: usize, leaves: Vec<Digest>) -> Self {
        let mut zero = vec![[0u8; 32]];
        for l in 0..depth {
            zero.push(node::<H>(&zero[l], &zero[l]));
        }
        let mut levels = vec![leaves];
        for l in 0..depth {
            let cur = &levels[l];
            let next = (0..cur.len().div_ceil(2))
                .map(|i| node::<H>(&cur[2 * i], cur.get(2 * i + 1).unwrap_or(&zero[l])))
                .collect();
            levels.push(next);
        }
        Tree { depth, levels, zero }
    }

    pub fn root(&self) -> Digest {
        *self.levels[self.depth].first().unwrap_or(&self.zero[self.depth])
    }

    pub fn path(&self, idx: usize) -> Vec<Digest> {
        (0..self.depth).map(|l| *self.levels[l].get((idx >> l) ^ 1).unwrap_or(&self.zero[l])).collect()
    }
}

/// Lamport one-time key over SHA-256 (secrets from a PRF of the epoch seed).
pub fn lamport_key(seed: &Digest, leaf: u32) -> (Vec<[Digest; 2]>, Vec<[Digest; 2]>) {
    let sk: Vec<[Digest; 2]> = (0..256u32)
        .map(|i| {
            let s = |b: u32| sha(&[b"zkmob/ots-sk", seed, &leaf.to_le_bytes(), &(2 * i + b).to_le_bytes()]);
            [s(0), s(1)]
        })
        .collect();
    let pk = sk.iter().map(|s| [tagged::<H>(b"zkmob/ots", &[&s[0]]), tagged::<H>(b"zkmob/ots", &[&s[1]])]).collect();
    (sk, pk)
}

/// One epoch subtree of 2^depth Lamport keys (stateful: `next` only grows).
pub struct Epoch {
    seed: Digest,
    pub tree: Tree,
    next: u32,
}

impl Epoch {
    pub fn generate(seed: Digest, depth: usize) -> Self {
        let leaves = (0..1u32 << depth).map(|i| lamport_pk_hash::<H>(&lamport_key(&seed, i).1)).collect();
        Epoch { seed, tree: Tree::new(depth, leaves), next: 0 }
    }

    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    /// Resume a stateful epoch whose first `next` keys are already used.
    pub fn resume(seed: Digest, depth: usize, next: u32) -> Self {
        let mut e = Self::generate(seed, depth);
        e.next = next;
        e
    }

    /// Sign m with the next unused one-time key: (leaf index, signature, path).
    pub fn sign(&mut self, m: &Digest) -> (u32, LamportSig, Vec<Digest>) {
        let leaf = self.next;
        assert!((leaf as usize) < 1 << self.tree.depth, "epoch exhausted");
        self.next += 1;
        let (sk, pk) = lamport_key(&self.seed, leaf);
        let sig = LamportSig {
            reveal: (0..256).map(|i| sk[i][bit(m, i) as usize]).collect(),
            other: (0..256).map(|i| pk[i][1 - bit(m, i) as usize]).collect(),
        };
        (leaf, sig, self.tree.path(leaf as usize))
    }
}

/// Everything needed to answer queries about one signed trace.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedTrace {
    pub traj: Vec<Point>,
    pub blind: [u8; 32],
    pub sig: LamportSig,
    pub leaf_index: u32,
    pub epoch_path: Vec<Digest>,
    pub reg_index: u32,
    pub reg_path: Vec<Digest>,
    pub reg_root: Digest,
}

impl SignedTrace {
    pub fn witness(&self, slot: u32) -> Witness {
        Witness {
            traj: self.traj.clone(),
            blind: self.blind,
            sig: self.sig.clone(),
            leaf_index: self.leaf_index,
            epoch_path: self.epoch_path.clone(),
            reg_index: self.reg_index,
            reg_path: self.reg_path.clone(),
            slot,
        }
    }
}

/// Device records `traj`, commits with a fresh blinding value, signs with its
/// epoch key; the epoch root sits at `reg_index` in a registry of `others`
/// other epoch roots (depth `reg_depth`).
/// Reproducible benchmark fixture, NOT confidential deployment setup:
/// epoch secrets are fixed, the blind is length-derived, and registry leaves
/// are constructed directly rather than admitted via ML-DSA certificates.
/// Known candidate traces can therefore be tested against public nullifiers.
/// See code/A_PREMISES.md before using this path for any privacy claim.
pub fn setup_fixture(traj: Vec<Point>, epoch_depth: usize, reg_depth: usize, others: usize) -> SignedTrace {
    let mut epoch = Epoch::generate(sha(&[b"device-1/epoch-1"]), epoch_depth);
    let blind: [u8; 32] = sha(&[b"blind", &(traj.len() as u32).to_le_bytes()]);
    let c = commit::<H>(&traj, &blind);
    let (leaf_index, sig, epoch_path) = epoch.sign(&c);
    let mut leaves: Vec<Digest> = (0..others).map(|i| sha(&[b"other-epoch", &(i as u32).to_le_bytes()])).collect();
    let reg_index = leaves.len() as u32;
    leaves.push(epoch.root());
    let reg = Tree::new(reg_depth, leaves);
    SignedTrace { traj, blind, sig, leaf_index, epoch_path, reg_index, reg_path: reg.path(reg_index as usize), reg_root: reg.root() }
}

/// Fresh OS entropy for a local signed-trace setup. Unlike setup_fixture,
/// the blind and signing seed are secret and independent of the trajectory.
/// This still builds a LOCAL registry, not ML-DSA-certified admission.
/// Persist the returned SignedTrace once; regenerating it resets C/budgets.
pub fn setup_randomized_local(traj: Vec<Point>, epoch_depth: usize, reg_depth: usize, others: usize) -> std::io::Result<SignedTrace> {
    use std::io::Read;
    if epoch_depth > 16 || reg_depth > 31 || others >= (1usize << reg_depth) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid setup tree size"));
    }
    let mut entropy = std::fs::File::open("/dev/urandom")?;
    let mut seed = [0u8; 32];
    let mut blind = [0u8; 32];
    entropy.read_exact(&mut seed)?;
    entropy.read_exact(&mut blind)?;
    let mut epoch = Epoch::generate(seed, epoch_depth);
    let c = commit::<H>(&traj, &blind);
    let (leaf_index, sig, epoch_path) = epoch.sign(&c);
    let mut leaves = Vec::with_capacity(others + 1);
    for _ in 0..others {
        let mut leaf = [0u8; 32];
        entropy.read_exact(&mut leaf)?;
        leaves.push(leaf);
    }
    let reg_index = leaves.len() as u32;
    leaves.push(epoch.root());
    let reg = Tree::new(reg_depth, leaves);
    Ok(SignedTrace { traj, blind, sig, leaf_index, epoch_path, reg_index,
        reg_path: reg.path(reg_index as usize), reg_root: reg.root() })
}

pub fn load_trace(path: &str, n: usize) -> Vec<Point> { load_trace_nth(path, n, 0) }

/// The first n fixes of the k-th trace (0-based) that has at least n fixes.
pub fn load_trace_nth(path: &str, n: usize, k: usize) -> Vec<Point> {
    use std::io::BufRead;
    let f = std::io::BufReader::new(std::fs::File::open(path).expect("open traces (run zkmob.n1_export first)"));
    let mut seen = 0;
    for line in f.lines() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let pts = v["points"].as_array().unwrap();
        if pts.len() >= n && { seen += 1; seen > k } {
            return pts[..n]
                .iter()
                .map(|p| Point { x: p[0].as_u64().unwrap() as u32, y: p[1].as_u64().unwrap() as u32, t: p[2].as_u64().unwrap() as u32 })
                .collect();
        }
    }
    panic!("no trace with >= {n} points");
}

/// "A near fix i, then B near fix j within f * observed gap".
pub fn policy_between(traj: &[Point], i: usize, j: usize, f: f64) -> Policy {
    let around = |p: &Point| BoxZone { xmin: p.x.saturating_sub(100), xmax: p.x + 100, ymin: p.y.saturating_sub(100), ymax: p.y + 100 };
    let gap = ((traj[j].t - traj[i].t) as f64 * f) as u32;
    Policy { steps: vec![Step { zone: around(&traj[i]), max_gap: None }, Step { zone: around(&traj[j]), max_gap: Some(gap) }], avoid: None }
}
