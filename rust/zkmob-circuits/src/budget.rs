//! Bounded disclosure per device (claim N5): exact yes/no answers plus a
//! per-verifier, per-period query budget enforced with nullifiers.
//!
//! **Scan circuit (either outcome).** `enforce_scan_policy` evaluates the
//! policy over the whole private trace and outputs the outcome bit, so the
//! prover can prove "holds" AND "does not hold". This matters for the
//! budget: if only true policies produced proofs, every "no" answer would
//! be free (a refusal is itself a bit) and a budget on proofs would not
//! bound leakage. Semantics = `types::find_witness` (tested). One pass
//! keeps, for each step s, whether a partial match of steps 1..s exists
//! among the earlier fixes and the LATEST time it can end; the latest end
//! is optimal because gaps only bound t_j - t_i and the trace is
//! time-sorted (which the circuit enforces). Cost O(n * k).
//!
//! **Budgeted relation** (`BudgetedCircuit`), public: policy, outcome b,
//! registry root R, verifier id V, budget B, period p, nullifier N; witness as in
//! `unlinkable.rs` plus a slot j:
//!   C = Poseidon(r || T) is signed by a registered epoch key,
//!   b = Policy(T),  0 <= j < B,  N = Poseidon(TAG_NULL || k_D || V || p || j)
//! for the device budget key k_D and the public budget period p.
//! The verifier stores the nullifiers it has accepted and rejects repeats.
//! This prevents ACCEPTANCE replay only: a malicious verifier can ignore the
//! rule, and a released proof has already disclosed its answer. The bound on
//! RELEASED answers is enforced by the prover-side wallet state machine
//! (reserve-before-release, both outcomes charged, no refunds; see
//! `zkvm/host/src/wallet.rs` and code/A_PREMISES.md, premise A3).
//! Unlinkability of the proofs requires N to be pseudorandom across slots,
//! periods and verifiers; with a uniform k_D this holds in the random-oracle
//! model (paper, Theorem 2 and Lemma 3).
//!
//! Assumptions (stated in the paper): V is an authenticated verifier
//! identity (otherwise Sybil verifiers each get B answers); the registry
//! admits one budget tag per device (a second key would give a fresh
//! budget); the budget renews per period p, which the wallet reads from its
//! own clock, so leakage over P periods is bounded by 2^{mBP} p_0.

use std::collections::HashSet;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::commit::{commit_native_hiding, poseidon_config};
use crate::gadgets::*;
use crate::ordered::{alloc_policy, alloc_trajectory, flatten_vars, policy_public_inputs, PolicyVars};
use crate::sig::{field_bytes, hash_gadget, DeviceSig, Hasher};
use crate::types::*;
use crate::unlinkable::enforce_signed_commitment;

pub const TAG_NULL: u64 = 0x0011;
/// Bit width of slot indices and budgets.
pub const SLOT_BITS: usize = 16;

/// Native scan evaluation (same algorithm as the circuit).
pub fn scan_eval(traj: &[Point], steps: &[Step], avoid: Option<&BoxZone>) -> bool {
    let k = steps.len();
    let mut has = vec![false; k];
    let mut last = vec![0u64; k];
    let mut violated = false;
    for p in traj {
        for s in (0..k).rev() {
            let inz = steps[s].zone.contains(p);
            let ok = s == 0
                || (has[s - 1] && steps[s].max_gap.is_none_or(|g| p.t - last[s - 1] <= g));
            if inz && ok {
                has[s] = true;
                last[s] = p.t;
            }
        }
        violated |= avoid.is_some_and(|z| z.contains(p));
    }
    has[k - 1] && !violated
}

/// In-circuit scan; returns the outcome bit. Also enforces that the trace
/// is time-sorted and all values are in range.
pub fn enforce_scan_policy<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    pol: &PolicyVars<F>,
    xs: &[FpVar<F>],
    ys: &[FpVar<F>],
    ts: &[FpVar<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let k = pol.zones.len();
    let mut has: Vec<Boolean<F>> = vec![Boolean::FALSE; k];
    let mut last: Vec<FpVar<F>> = vec![FpVar::zero(); k];
    let mut violated = Boolean::FALSE;
    for j in 0..xs.len() {
        enforce_in_range(cs.clone(), &xs[j], COORD_BITS)?;
        enforce_in_range(cs.clone(), &ys[j], COORD_BITS)?;
        enforce_in_range(cs.clone(), &ts[j], TIME_BITS)?;
        if j > 0 {
            enforce_leq(cs.clone(), &ts[j - 1], &ts[j], TIME_BITS)?;
        }
        for s in (0..k).rev() {
            let inz = in_box(cs.clone(), &xs[j], &ys[j], &pol.zones[s], COORD_BITS)?;
            let hit = if s == 0 {
                inz
            } else {
                let ok = match &pol.gaps[s] {
                    // t_j - last >= 0 because the trace is sorted and last is an earlier t
                    Some(g) => &has[s - 1] & &is_leq(cs.clone(), &(&ts[j] - &last[s - 1]), g, TIME_BITS)?,
                    None => has[s - 1].clone(),
                };
                &inz & &ok
            };
            has[s] = &has[s] | &hit;
            last[s] = FpVar::conditionally_select(&hit, &ts[j], &last[s])?;
        }
        if let Some(z) = &pol.avoid {
            violated = &violated | &in_box(cs.clone(), &xs[j], &ys[j], z, COORD_BITS)?;
        }
    }
    Ok(&has[k - 1] & &!&violated)
}

/// Stand-alone scan circuit (no signature): public = policy || outcome.
/// Used to measure the policy part and to test the scan semantics.
#[derive(Clone)]
pub struct ScanPolicyCircuit {
    pub traj: Vec<Point>,
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
    pub outcome: bool,
}

impl ScanPolicyCircuit {
    pub fn public_inputs<F: PrimeField>(&self) -> Vec<F> {
        let mut v = policy_public_inputs(&self.steps, self.avoid.as_ref());
        v.push(F::from(self.outcome));
        v
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ScanPolicyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pol = alloc_policy(&cs, &self.steps, self.avoid.as_ref())?;
        let b = Boolean::new_input(cs.clone(), || Ok(self.outcome))?;
        let (xs, ys, ts) = alloc_trajectory(&cs, &self.traj)?;
        enforce_scan_policy(&cs, &pol, &xs, &ys, &ts)?.enforce_equal(&b)
    }
}

/// Device nullifier H(k_D || V || p || j) for budget period p (review
/// round 2, NEW-01: budgets renew per period instead of never).
pub fn nullifier<F: PrimeField + Absorb>(h: &Hasher<F>, k: F, verifier: F, period: u64, slot: u64) -> F {
    h.hash(TAG_NULL, &[k, verifier, F::from(period), F::from(slot)])
}

#[derive(Clone)]
pub struct BudgetedCircuit<F: PrimeField> {
    pub traj: Vec<Point>,
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
    pub outcome: bool,
    pub blind: u128,
    /// Device budget key k_D; its tag is bound into the registry leaf.
    pub dev_key: F,
    pub sig: DeviceSig<F>,
    pub reg_index: usize,
    pub reg_path: Vec<F>,
    pub reg_root: F,
    pub verifier: F,
    pub budget: u64,
    /// Public budget period (e.g. calendar month); the verifier checks it is
    /// the current one, and the wallet grants B slots per (verifier, period).
    pub period: u64,
    pub slot: u64,
}

impl<F: PrimeField + Absorb> BudgetedCircuit<F> {
    pub fn commitment(&self) -> F {
        commit_native_hiding(&poseidon_config::<F>(), &self.traj, self.blind)
    }

    /// Device-level nullifier H(k_D || V || p || j): shared across traces.
    pub fn nullifier(&self, h: &Hasher<F>) -> F {
        nullifier(h, self.dev_key, self.verifier, self.period, self.slot)
    }

    /// policy || outcome || R || V || B || p || N
    pub fn public_inputs(&self, h: &Hasher<F>) -> Vec<F> {
        let mut v = policy_public_inputs(&self.steps, self.avoid.as_ref());
        v.extend([F::from(self.outcome), self.reg_root, self.verifier, F::from(self.budget), F::from(self.period), self.nullifier(h)]);
        v
    }
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for BudgetedCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = poseidon_config::<F>();
        let h = Hasher { cfg: cfg.clone() };
        let pol = alloc_policy(&cs, &self.steps, self.avoid.as_ref())?;
        let b = Boolean::new_input(cs.clone(), || Ok(self.outcome))?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.reg_root))?;
        let v = FpVar::new_input(cs.clone(), || Ok(self.verifier))?;
        let budget = FpVar::new_input(cs.clone(), || Ok(F::from(self.budget)))?;
        let period = FpVar::new_input(cs.clone(), || Ok(F::from(self.period)))?;
        let n_pub = FpVar::new_input(cs.clone(), || Ok(self.nullifier(&h)))?;

        let (xs, ys, ts) = alloc_trajectory(&cs, &self.traj)?;
        let k = FpVar::new_witness(cs.clone(), || Ok(self.dev_key))?;
        let tag = hash_gadget(cs.clone(), &cfg, crate::sig::TAG_DEVKEY, &[k.clone()])?;
        let _c = enforce_signed_commitment(&cs, &cfg, flatten_vars(&xs, &ys, &ts), self.blind, &self.sig,
            self.reg_index, &self.reg_path, &root, Some(&tag))?;

        // 0 <= j < B  (j + 1 <= B, both range-checked)
        let j = FpVar::new_witness(cs.clone(), || Ok(F::from(self.slot)))?;
        enforce_in_range(cs.clone(), &j, SLOT_BITS)?;
        enforce_in_range(cs.clone(), &budget, SLOT_BITS)?;
        enforce_leq(cs.clone(), &(&j + FpVar::one()), &budget, SLOT_BITS)?;
        hash_gadget(cs.clone(), &cfg, TAG_NULL, &[k, v, period, j])?.enforce_equal(&n_pub)?;

        enforce_scan_policy(&cs, &pol, &xs, &ys, &ts)?.enforce_equal(&b)
    }
}

/// Verifier-side state: accepted nullifiers, per verifier id.
#[derive(Default)]
pub struct NullifierLog {
    seen: HashSet<Vec<u8>>,
}

impl NullifierLog {
    /// Record `n` for verifier `v`; false if it was already used.
    pub fn accept<F: PrimeField>(&mut self, v: &F, n: &F) -> bool {
        let mut key = field_bytes(v);
        key.extend(field_bytes(n));
        self.seen.insert(key)
    }
}

/// Prover-side slot allocation per (device budget key, verifier, period): the next unused slot,
/// or `None` when the budget is spent (the prover then refuses).
/// Demo-only RAM state. This does not persist across restart, freeze a cap,
/// or bind retries to a policy. Verifier-side nullifier rejection cannot
/// substitute for wallet-side release enforcement; see code/A_PREMISES.md.
#[derive(Default)]
pub struct SlotWallet {
    used: std::collections::HashMap<Vec<u8>, u64>,
}

impl SlotWallet {
    pub fn next<F: PrimeField>(&mut self, dev_key: &F, v: &F, period: u64, budget: u64) -> Option<u64> {
        let mut key = field_bytes(dev_key);
        key.extend(field_bytes(v));
        key.extend(period.to_le_bytes());
        let u = self.used.entry(key).or_insert(0);
        if *u >= budget {
            return None;
        }
        *u += 1;
        Some(*u - 1)
    }
}
