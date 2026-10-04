//! Our design (pilot version): prove an ordered, relatively-timed policy by
//! letting the prover *select* the witnessing points with one-hot selectors,
//! instead of scanning a discretised symbol stream through an automaton.
//!
//! Statement (public: zones, gaps, optional avoid zone, optional commitment):
//!   exists i_1 < ... < i_k with p[i_s] in zone_s,
//!   0 <= t[i_s] - t[i_{s-1}] <= max_gap_s   (when a gap is given),
//!   and (optionally) no point of the trajectory lies in `avoid`,
//!   and (optionally) Poseidon([r ||] trajectory) == public commitment.
//!
//! Cost is O(k * n) for selection plus O(k * bits) for the checks.
//! Crucially it does NOT depend on the time resolution of `max_gap`:
//! timestamps are compared as 32-bit integers.

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::commit::{enforce_commitment, Commit};
use crate::gadgets::*;
use crate::types::*;

#[derive(Clone)]
pub struct OrderedPolicyCircuit {
    pub traj: Vec<Point>,
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
    /// Prover's witness indices (one per step). `None` during setup.
    pub witness: Option<Vec<usize>>,
    /// Bind the trajectory to a public Poseidon commitment (see `Commit`).
    pub commit: Commit,
}

fn bits_for(n: usize) -> usize {
    (usize::BITS - n.max(1).leading_zeros()) as usize
}

/// Exact R1CS constraint count of `OrderedPolicyCircuit` without avoidance
/// or commitment: n points, s steps, of which `gapped` carry a max_gap.
/// Per step: one-hot over n (n + 1), three selects (3n), three range
/// checks (3 * 33) and a box check (4 * 33). Per later step: index order
/// (bits(n) + 1) and time order (33); each gap adds 33.
pub fn ours_constraints(n: usize, s: usize, gapped: usize) -> usize {
    use crate::types::{COORD_BITS as C, TIME_BITS as T};
    // per step: x, y, t range checks + box check + one-hot selection;
    // per order constraint: index order + time order; per gap: one comparison
    s * (6 * C + T + 8 + 4 * n) + s.saturating_sub(1) * (bits_for(n) + T + 2) + gapped * (T + 1)
}

pub(crate) fn bits_for_pub(n: usize) -> usize { bits_for(n) }

/// Public policy parameters of the ordered circuit, in allocation order.
pub fn policy_public_inputs<F: PrimeField>(steps: &[Step], avoid: Option<&BoxZone>) -> Vec<F> {
    let mut v = Vec::new();
    for s in steps {
        v.extend([s.zone.xmin, s.zone.xmax, s.zone.ymin, s.zone.ymax].map(F::from));
        if let Some(g) = s.max_gap {
            v.push(F::from(g));
        }
    }
    if let Some(z) = avoid {
        v.extend([z.xmin, z.xmax, z.ymin, z.ymax].map(F::from));
    }
    v
}

impl OrderedPolicyCircuit {
    /// Public inputs in allocation order (needed by the Groth16 verifier).
    pub fn public_inputs<F: PrimeField + Absorb>(&self) -> Vec<F> {
        let mut v = policy_public_inputs(&self.steps, self.avoid.as_ref());
        v.extend(self.commit.value::<F>(&self.traj));
        v
    }
}

/// Allocated public policy parameters.
pub struct PolicyVars<F: PrimeField> {
    pub zones: Vec<[FpVar<F>; 4]>,
    pub gaps: Vec<Option<FpVar<F>>>,
    pub avoid: Option<[FpVar<F>; 4]>,
}

fn alloc_box<F: PrimeField>(cs: &ConstraintSystemRef<F>, z: &BoxZone) -> Result<[FpVar<F>; 4], SynthesisError> {
    Ok([
        FpVar::new_input(cs.clone(), || Ok(F::from(z.xmin)))?,
        FpVar::new_input(cs.clone(), || Ok(F::from(z.xmax)))?,
        FpVar::new_input(cs.clone(), || Ok(F::from(z.ymin)))?,
        FpVar::new_input(cs.clone(), || Ok(F::from(z.ymax)))?,
    ])
}

/// Allocate the policy parameters as public inputs (same order as
/// `policy_public_inputs`).
pub fn alloc_policy<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    steps: &[Step],
    avoid: Option<&BoxZone>,
) -> Result<PolicyVars<F>, SynthesisError> {
    let mut zones = Vec::new();
    let mut gaps = Vec::new();
    for s in steps {
        zones.push(alloc_box(cs, &s.zone)?);
        gaps.push(match s.max_gap {
            Some(g) => Some(FpVar::new_input(cs.clone(), || Ok(F::from(g)))?),
            None => None,
        });
    }
    let avoid = match avoid {
        Some(z) => Some(alloc_box(cs, z)?),
        None => None,
    };
    Ok(PolicyVars { zones, gaps, avoid })
}

/// Allocate the private trajectory; returns (xs, ys, ts).
pub fn alloc_trajectory<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    traj: &[Point],
) -> Result<(Vec<FpVar<F>>, Vec<FpVar<F>>, Vec<FpVar<F>>), SynthesisError> {
    let (mut xs, mut ys, mut ts) = (Vec::new(), Vec::new(), Vec::new());
    for p in traj {
        xs.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.x)))?);
        ys.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.y)))?);
        ts.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.t)))?);
    }
    Ok((xs, ys, ts))
}

/// Interleave to [x0, y0, t0, x1, ...] (the commitment's absorption order).
pub fn flatten_vars<F: PrimeField>(xs: &[FpVar<F>], ys: &[FpVar<F>], ts: &[FpVar<F>]) -> Vec<FpVar<F>> {
    (0..xs.len()).flat_map(|i| [xs[i].clone(), ys[i].clone(), ts[i].clone()]).collect()
}

/// The policy relation itself: ordered steps with gaps, plus avoidance.
pub fn enforce_policy<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    pol: &PolicyVars<F>,
    xs: &[FpVar<F>],
    ys: &[FpVar<F>],
    ts: &[FpVar<F>],
    witness: Option<&[usize]>,
) -> Result<(), SynthesisError> {
    let n = xs.len();
    let ib = bits_for(n);
    let mut prev: Option<(FpVar<F>, FpVar<F>)> = None; // (index, time)
    for s in 0..pol.zones.len() {
        let idx = witness.map(|w| w[s]);
        let (sel, index) = alloc_onehot(cs.clone(), n, idx)?;
        let x = select(&sel, xs)?;
        let y = select(&sel, ys)?;
        let t = select(&sel, ts)?;
        // Range-check the selected values (soundness against wrap-around).
        enforce_in_range(cs.clone(), &x, COORD_BITS)?;
        enforce_in_range(cs.clone(), &y, COORD_BITS)?;
        enforce_in_range(cs.clone(), &t, TIME_BITS)?;
        enforce_in_box(cs.clone(), &x, &y, &pol.zones[s], COORD_BITS)?;
        if let Some((pi, pt)) = &prev {
            // strict index order: index - prev - 1 >= 0
            let d = &index - pi - FpVar::one();
            enforce_in_range(cs.clone(), &d, ib)?;
            // time order and gap
            enforce_leq(cs.clone(), pt, &t, TIME_BITS)?;
            if let Some(g) = &pol.gaps[s] {
                let dt = &t - pt;
                enforce_leq(cs.clone(), &dt, g, TIME_BITS)?;
            }
        }
        prev = Some((index, t));
    }

    // Avoidance: every point outside the restricted box (full scan).
    if let Some(z) = &pol.avoid {
        for i in 0..n {
            enforce_in_range(cs.clone(), &xs[i], COORD_BITS)?;
            enforce_in_range(cs.clone(), &ys[i], COORD_BITS)?;
            let inside = in_box(cs.clone(), &xs[i], &ys[i], z, COORD_BITS)?;
            inside.enforce_equal(&Boolean::FALSE)?;
        }
    }
    Ok(())
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for OrderedPolicyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pol = alloc_policy(&cs, &self.steps, self.avoid.as_ref())?;
        let (xs, ys, ts) = alloc_trajectory(&cs, &self.traj)?;
        // Binding to the committed / signed trajectory. The commitment is
        // the last public input (allocated after the policy parameters).
        enforce_commitment(cs.clone(), self.commit, &self.traj, flatten_vars(&xs, &ys, &ts))?;
        enforce_policy(&cs, &pol, &xs, &ys, &ts, self.witness.as_deref())
    }
}
