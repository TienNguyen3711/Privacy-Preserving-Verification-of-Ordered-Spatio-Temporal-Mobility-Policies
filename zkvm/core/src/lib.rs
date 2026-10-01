//! The budgeted, unlinkable policy relation (same structure as the arkworks
//! `BudgetedCircuit`), written as plain Rust so it can run inside the RISC
//! Zero zkVM. All hashing is SHA-256 (accelerated in the zkVM), so here:
//!
//!   C      = H("zkmob/commit" || r || T)                  hiding commitment
//!   leaf   = LamportPK(C, sig)   (Lamport over SHA-256, 256 message bits)
//!   E      = MerkleRoot(leaf, epoch path)                 epoch subtree root
//!   R      = MerkleRoot(E, registry path)                 public registry root
//!   b      = Policy(T)          (one-pass scan, proves yes or no exactly)
//!   j < B,  N = H("zkmob/null" || C || V || j)            budget nullifier
//!
//! Public (journal): policy, b, R, V, B, N. Everything else is private.
//! The hash is a parameter (`Hasher`) so host and guest share this code.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub type Digest = [u8; 32];

/// SHA-256 over a byte string (the guest plugs in the zkVM accelerator).
pub trait Hasher {
    fn hash(data: &[u8]) -> Digest;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    pub x: u32,
    pub y: u32,
    pub t: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxZone {
    pub xmin: u32,
    pub xmax: u32,
    pub ymin: u32,
    pub ymax: u32,
}

impl BoxZone {
    pub fn contains(&self, p: &Point) -> bool {
        self.xmin <= p.x && p.x <= self.xmax && self.ymin <= p.y && p.y <= self.ymax
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub zone: BoxZone,
    pub max_gap: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
}

/// Lamport signature: for each of the 256 message bits, the revealed
/// preimage and the public value of the other bit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LamportSig {
    pub reveal: Vec<Digest>,
    pub other: Vec<Digest>,
}

/// Private input of the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub traj: Vec<Point>,
    /// 256-bit blind: a 128-bit blind gives only about q*2^-64 against quantum
    /// hash queries in the unlinkability hybrid (paper, App. D).
    pub blind: [u8; 32],
    pub sig: LamportSig,
    pub leaf_index: u32,
    pub epoch_path: Vec<Digest>,
    pub reg_index: u32,
    pub reg_path: Vec<Digest>,
    pub slot: u32,
}

impl Witness {
    /// Compact byte encoding (little-endian u32s, raw digests). The zkVM's
    /// default serde codec spends one 32-bit word per byte of a digest, which
    /// made reading the 16 kB signature cost 90% of all guest cycles.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let u = |b: &mut Vec<u8>, x: u32| b.extend_from_slice(&x.to_le_bytes());
        u(&mut b, self.traj.len() as u32);
        for p in &self.traj {
            u(&mut b, p.x);
            u(&mut b, p.y);
            u(&mut b, p.t);
        }
        b.extend_from_slice(&self.blind);
        u(&mut b, self.sig.reveal.len() as u32);
        for d in self.sig.reveal.iter().chain(&self.sig.other) {
            b.extend_from_slice(d);
        }
        u(&mut b, self.leaf_index);
        u(&mut b, self.epoch_path.len() as u32);
        for d in &self.epoch_path {
            b.extend_from_slice(d);
        }
        u(&mut b, self.reg_index);
        u(&mut b, self.reg_path.len() as u32);
        for d in &self.reg_path {
            b.extend_from_slice(d);
        }
        u(&mut b, self.slot);
        b
    }

    /// Inverse of `to_bytes`; panics on malformed input.
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut pos = 0usize;
        let mut take = |n: usize| -> &[u8] {
            let s = &b[pos..pos + n];
            pos += n;
            s
        };
        fn u32_of(s: &[u8]) -> u32 {
            u32::from_le_bytes(s.try_into().unwrap())
        }
        fn dig(s: &[u8]) -> Digest {
            s.try_into().unwrap()
        }
        let n = u32_of(take(4)) as usize;
        let traj = (0..n).map(|_| Point { x: u32_of(take(4)), y: u32_of(take(4)), t: u32_of(take(4)) }).collect();
        let blind: [u8; 32] = take(32).try_into().unwrap();
        let k = u32_of(take(4)) as usize;
        let reveal = (0..k).map(|_| dig(take(32))).collect();
        let other = (0..k).map(|_| dig(take(32))).collect();
        let leaf_index = u32_of(take(4));
        let e = u32_of(take(4)) as usize;
        let epoch_path = (0..e).map(|_| dig(take(32))).collect();
        let reg_index = u32_of(take(4));
        let r = u32_of(take(4)) as usize;
        let reg_path = (0..r).map(|_| dig(take(32))).collect();
        let slot = u32_of(take(4));
        assert!(pos == b.len(), "trailing witness bytes");
        Witness { traj, blind, sig: LamportSig { reveal, other }, leaf_index, epoch_path, reg_index, reg_path, slot }
    }
}

/// Public input of the guest (policy and verifier context).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub policy: Policy,
    pub reg_root: Digest,
    pub verifier: Digest,
    pub budget: u32,
}

/// What the proof publishes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub statement: Statement,
    pub outcome: bool,
    pub nullifier: Digest,
}

pub fn commit<H: Hasher>(traj: &[Point], blind: &[u8; 32]) -> Digest {
    let mut buf = Vec::with_capacity(12 + 32 + 12 * traj.len());
    buf.extend_from_slice(b"zkmob/commit");
    buf.extend_from_slice(blind);
    for p in traj {
        buf.extend_from_slice(&p.x.to_le_bytes());
        buf.extend_from_slice(&p.y.to_le_bytes());
        buf.extend_from_slice(&p.t.to_le_bytes());
    }
    H::hash(&buf)
}

pub fn tagged<H: Hasher>(tag: &[u8], parts: &[&[u8]]) -> Digest {
    let mut buf = Vec::with_capacity(tag.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    buf.extend_from_slice(tag);
    for p in parts {
        buf.extend_from_slice(p);
    }
    H::hash(&buf)
}

pub fn node<H: Hasher>(l: &Digest, r: &Digest) -> Digest {
    tagged::<H>(b"zkmob/node", &[l, r])
}

pub fn bit(m: &Digest, i: usize) -> bool {
    (m[i / 8] >> (i % 8)) & 1 == 1
}

/// Lamport one-time public-key hash from the two public values per bit.
pub fn lamport_pk_hash<H: Hasher>(pk: &[[Digest; 2]]) -> Digest {
    let mut buf = Vec::with_capacity(9 + 64 * pk.len());
    buf.extend_from_slice(b"zkmob/pk");
    for p in pk {
        buf.extend_from_slice(&p[0]);
        buf.extend_from_slice(&p[1]);
    }
    H::hash(&buf)
}

/// Recompute the one-time public-key hash from (message, signature).
pub fn lamport_verify<H: Hasher>(m: &Digest, sig: &LamportSig) -> Digest {
    assert!(sig.reveal.len() == 256 && sig.other.len() == 256, "malformed signature");
    let pk: Vec<[Digest; 2]> = (0..256)
        .map(|i| {
            let h = tagged::<H>(b"zkmob/ots", &[&sig.reveal[i]]);
            if bit(m, i) { [sig.other[i], h] } else { [h, sig.other[i]] }
        })
        .collect();
    lamport_pk_hash::<H>(&pk)
}

pub fn merkle_root<H: Hasher>(leaf: Digest, index: u32, path: &[Digest]) -> Digest {
    let mut cur = leaf;
    for (l, sib) in path.iter().enumerate() {
        cur = if (index >> l) & 1 == 1 { node::<H>(sib, &cur) } else { node::<H>(&cur, sib) };
    }
    cur
}

/// Largest number of ordered steps the scan supports.
pub const MAX_STEPS: usize = 8;

/// Public admission check for the supported policy domain. It depends only on
/// the public policy, never on the trace, so a wallet can run it before
/// reserving a slot; every policy it accepts is evaluated by `scan_eval`
/// without panicking (given a time-sorted trace).
pub fn validate_policy(policy: &Policy) -> Result<(), &'static str> {
    if policy.steps.is_empty() { return Err("policy needs at least one step"); }
    if policy.steps.len() > MAX_STEPS { return Err("at most 8 steps"); }
    if policy.steps[0].max_gap.is_some() { return Err("no gap on the first step"); }
    for zone in policy.steps.iter().map(|s| &s.zone).chain(policy.avoid.iter()) {
        if zone.xmin > zone.xmax || zone.ymin > zone.ymax { return Err("invalid zone"); }
    }
    Ok(())
}

/// One-pass policy evaluation (same algorithm as rust `budget::scan_eval`).
/// Requires a time-sorted trace (checked) and a policy accepted by
/// `validate_policy`.
pub fn scan_eval(traj: &[Point], policy: &Policy) -> bool {
    let k = policy.steps.len();
    assert!(k >= 1, "empty policy");
    let mut has = [false; MAX_STEPS];
    let mut last = [0u32; MAX_STEPS];
    assert!(k <= MAX_STEPS, "at most 8 steps");
    let mut violated = false;
    for (j, p) in traj.iter().enumerate() {
        if j > 0 {
            assert!(traj[j - 1].t <= p.t, "trace not time-sorted");
        }
        for s in (0..k).rev() {
            let st = &policy.steps[s];
            let ok = s == 0 || (has[s - 1] && st.max_gap.map_or(true, |g| p.t - last[s - 1] <= g));
            if st.zone.contains(p) && ok {
                has[s] = true;
                last[s] = p.t;
            }
        }
        if let Some(z) = &policy.avoid {
            violated |= z.contains(p);
        }
    }
    has[k - 1] && !violated
}

pub fn nullifier<H: Hasher>(c: &Digest, verifier: &Digest, slot: u32) -> Digest {
    tagged::<H>(b"zkmob/null", &[c, verifier, &slot.to_le_bytes()])
}

/// The whole relation: panics if the witness is invalid, otherwise returns
/// the journal to publish. This is exactly what the guest executes.
pub fn check<H: Hasher>(st: &Statement, w: &Witness) -> Journal {
    let c = commit::<H>(&w.traj, &w.blind);
    let leaf = lamport_verify::<H>(&c, &w.sig);
    let epoch_root = merkle_root::<H>(leaf, w.leaf_index, &w.epoch_path);
    let root = merkle_root::<H>(epoch_root, w.reg_index, &w.reg_path);
    assert!(root == st.reg_root, "signature does not chain to the registry root");
    assert!(w.slot < st.budget, "slot outside the budget");
    let outcome = scan_eval(&w.traj, &st.policy);
    Journal { statement: st.clone(), outcome, nullifier: nullifier::<H>(&c, &st.verifier, w.slot) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sha2::{Digest as _, Sha256};

    struct S;
    impl Hasher for S {
        fn hash(d: &[u8]) -> Digest {
            Sha256::digest(d).into()
        }
    }

    fn brute(traj: &[Point], pol: &Policy) -> bool {
        // exists i1 < ... < ik with zones, gaps and time order; no avoid hit
        fn rec(traj: &[Point], pol: &Policy, s: usize, start: usize, prev: Option<usize>) -> bool {
            if s == pol.steps.len() {
                return true;
            }
            (start..traj.len()).any(|i| {
                pol.steps[s].zone.contains(&traj[i])
                    && prev.map_or(true, |pi| {
                        traj[i].t >= traj[pi].t && pol.steps[s].max_gap.map_or(true, |g| traj[i].t - traj[pi].t <= g)
                    })
                    && rec(traj, pol, s + 1, i + 1, Some(i))
            })
        }
        rec(traj, pol, 0, 0, None) && !pol.avoid.map_or(false, |z| traj.iter().any(|p| z.contains(p)))
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self, m: u32) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((self.0 >> 33) as u32) % m
        }
        fn zone(&mut self) -> BoxZone {
            let (x, y) = (self.next(8), self.next(8));
            BoxZone { xmin: x, xmax: x + self.next(4), ymin: y, ymax: y + self.next(4) }
        }
    }

    #[test]
    fn scan_matches_bruteforce() {
        let mut r = Rng(7);
        let mut both = [0, 0];
        for _ in 0..3000 {
            let n = 1 + r.next(12) as usize;
            let mut t = 0;
            let traj: Vec<Point> = (0..n).map(|_| { t += r.next(20); Point { x: r.next(10), y: r.next(10), t } }).collect();
            let k = 1 + r.next(3) as usize;
            let steps = (0..k).map(|s| Step { zone: r.zone(), max_gap: if s > 0 && r.next(10) < 7 { Some(r.next(40)) } else { None } }).collect();
            let avoid = if r.next(10) < 3 { Some(r.zone()) } else { None };
            let pol = Policy { steps, avoid };
            let b = brute(&traj, &pol);
            assert_eq!(scan_eval(&traj, &pol), b);
            both[b as usize] += 1;
        }
        assert!(both[0] > 300 && both[1] > 300);
    }

    #[test]
    fn witness_bytes_roundtrip() {
        let w = Witness {
            traj: vec![Point { x: 1, y: 2, t: 3 }, Point { x: 4, y: 5, t: 6 }],
            blind: [7; 32],
            sig: LamportSig { reveal: vec![[1; 32]; 3], other: vec![[2; 32]; 3] },
            leaf_index: 9,
            epoch_path: vec![[3; 32]; 2],
            reg_index: 11,
            reg_path: vec![[4; 32]; 4],
            slot: 5,
        };
        let back = Witness::from_bytes(&w.to_bytes());
        assert_eq!((back.traj, back.blind, back.sig.reveal, back.sig.other), (w.traj.clone(), w.blind, w.sig.reveal.clone(), w.sig.other.clone()));
        assert_eq!((back.leaf_index, back.epoch_path, back.reg_index, back.reg_path, back.slot), (9, w.epoch_path, 11, w.reg_path, 5));
    }

    #[test]
    fn lamport_merkle_roundtrip() {
        let m = S::hash(b"message");
        let sk: Vec<[Digest; 2]> = (0..256u32).map(|i| [S::hash(&(2 * i).to_le_bytes()), S::hash(&(2 * i + 1).to_le_bytes())]).collect();
        let pk: Vec<[Digest; 2]> = sk.iter().map(|s| [tagged::<S>(b"zkmob/ots", &[&s[0]]), tagged::<S>(b"zkmob/ots", &[&s[1]])]).collect();
        let sig = LamportSig {
            reveal: (0..256).map(|i| sk[i][bit(&m, i) as usize]).collect(),
            other: (0..256).map(|i| pk[i][1 - bit(&m, i) as usize]).collect(),
        };
        assert_eq!(lamport_verify::<S>(&m, &sig), lamport_pk_hash::<S>(&pk));
        assert_ne!(lamport_verify::<S>(&S::hash(b"other"), &sig), lamport_pk_hash::<S>(&pk));
        let leaves = [S::hash(b"a"), S::hash(b"b"), S::hash(b"c"), S::hash(b"d")];
        let n01 = node::<S>(&leaves[0], &leaves[1]);
        let n23 = node::<S>(&leaves[2], &leaves[3]);
        let root = node::<S>(&n01, &n23);
        assert_eq!(merkle_root::<S>(leaves[2], 2, &vec![leaves[3], n01]), root);
    }

    #[test]
    fn validate_policy_matches_scan_domain() {
        let z = BoxZone { xmin: 0, xmax: 10, ymin: 0, ymax: 10 };
        let step = Step { zone: z, max_gap: None };
        let ok = Policy { steps: vec![step; MAX_STEPS], avoid: None };
        assert!(validate_policy(&ok).is_ok());
        scan_eval(&[Point { x: 1, y: 1, t: 0 }], &ok); // accepted policies never panic
        assert!(validate_policy(&Policy { steps: vec![step; MAX_STEPS + 1], avoid: None }).is_err());
        assert!(validate_policy(&Policy { steps: vec![], avoid: None }).is_err());
        let gap_first = Step { zone: z, max_gap: Some(5) };
        assert!(validate_policy(&Policy { steps: vec![gap_first], avoid: None }).is_err());
        let bad = BoxZone { xmin: 5, xmax: 1, ymin: 0, ymax: 0 };
        assert!(validate_policy(&Policy { steps: vec![step], avoid: Some(bad) }).is_err());
    }
}
