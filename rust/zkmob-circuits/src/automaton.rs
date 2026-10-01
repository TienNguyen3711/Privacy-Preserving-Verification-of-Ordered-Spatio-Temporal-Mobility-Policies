//! Baseline B3 model: "discretise, then run a regex/automaton in ZK"
//! (the route a reviewer would suggest via Reef / zkreg / Zombie).
//!
//! The trajectory is resampled into L = T / w time buckets (bucket width w
//! seconds). Each bucket's point is classified into a symbol
//! {A only, B only, A and B, other} inside the circuit (zones are public and
//! may overlap, so "both" needs its own symbol), and a DFA for the regex
//!     .* A .{0,k-1} B .*        with k = ceil(max_gap / w)
//! is run step by step. The DFA needs k + 2 states (a counter since the last
//! A), so finer time precision (smaller w) grows BOTH the number of steps L
//! and the number of states k.
//!
//! The per-step transition uses one-hot state vectors in plain R1CS, which is
//! pessimistic compared with Reef's lookup arguments. The pilot therefore also
//! reports L (steps) so that a lookup-based lower bound can be drawn:
//! even at one lookup per step the cost still grows as T / w.

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::commit::{enforce_commitment, Commit};
use crate::gadgets::*;
use crate::types::*;

/// Resample a time-sorted trajectory into buckets of width `w` seconds over
/// [0, horizon). Each bucket takes the last observed point at or before its
/// end (carry-forward), with the bucket's end time as timestamp.
pub fn resample(traj: &[Point], w: u64, horizon: u64) -> Vec<Point> {
    let l = horizon.div_ceil(w) as usize;
    let mut out = Vec::with_capacity(l);
    let mut j = 0usize;
    let mut last = traj[0];
    for b in 0..l {
        let end = (b as u64 + 1) * w;
        while j < traj.len() && traj[j].t < end {
            last = traj[j];
            j += 1;
        }
        out.push(Point { x: last.x, y: last.y, t: end });
    }
    out
}

/// Alternative discretisation for the native accuracy study ("any-fix"):
/// bucket b is flagged (in A, in B) if ANY recorded fix with timestamp in
/// [b*w, (b+1)*w) lies in A (resp. B); a bucket without fixes is "other".
/// Unlike carry-forward it never invents presence between sparse fixes, so
/// it is the most favourable discretisation for B3. Proving this
/// aggregation in-circuit costs extra; `b3_constraints` ignores that, so it
/// is a lower bound for this variant.
pub fn bucket_flags_any(traj: &[Point], a: &BoxZone, b: &BoxZone, w: u64, horizon: u64) -> Vec<(bool, bool)> {
    let l = horizon.div_ceil(w) as usize;
    let mut out = vec![(false, false); l];
    for p in traj {
        let i = (p.t / w) as usize;
        if i < l {
            out[i].0 |= a.contains(p);
            out[i].1 |= b.contains(p);
        }
    }
    out
}

/// Run the DFA on (in A, in B) flags.
pub fn dfa_accepts_flags(flags: &[(bool, bool)], k: usize) -> bool {
    let acc = k + 1;
    flags.iter().fold(0usize, |s, &(ia, ib)| next_state(s, ia, ib, k, acc)) == acc
}

/// Native DFA with the same state numbering as the circuit.
/// States: 0 = idle, 1..=k = buckets since last A (1 = A in this bucket),
/// k + 1 = accept (absorbing).
pub fn dfa_accepts(symbols: &[Point], a: &BoxZone, b: &BoxZone, k: usize) -> bool {
    let flags: Vec<(bool, bool)> = symbols.iter().map(|p| (a.contains(p), b.contains(p))).collect();
    dfa_accepts_flags(&flags, k)
}

/// A bucket in B closes an open window (B checked before A, so a bucket in
/// both zones can close a window AND a single bucket cannot serve as both
/// steps: at s = 0 it only opens a window).
fn next_state(s: usize, ia: bool, ib: bool, k: usize, acc: usize) -> usize {
    if s == acc {
        return acc;
    }
    if s >= 1 && ib {
        return acc;
    }
    if ia {
        return 1;
    }
    if s == 0 {
        0
    } else if s < k {
        s + 1
    } else {
        0
    }
}

#[derive(Clone)]
pub struct BucketAutomatonCircuit {
    /// Resampled trajectory, one point per bucket (length L).
    pub symbols: Vec<Point>,
    pub zone_a: BoxZone,
    pub zone_b: BoxZone,
    /// Counter bound k = ceil(max_gap / w).
    pub k: usize,
    pub commit: Commit,
}

impl BucketAutomatonCircuit {
    pub fn public_inputs<F: PrimeField + Absorb>(&self) -> Vec<F> {
        let mut v: Vec<F> = [self.zone_a, self.zone_b]
            .iter()
            .flat_map(|z| [z.xmin, z.xmax, z.ymin, z.ymax].map(F::from))
            .collect();
        v.extend(self.commit.value::<F>(&self.symbols));
        v
    }
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for BucketAutomatonCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let k = self.k;
        let nq = k + 2;
        let acc = k + 1;
        let alloc_box = |z: &BoxZone| -> Result<[FpVar<F>; 4], SynthesisError> {
            Ok([
                FpVar::new_input(cs.clone(), || Ok(F::from(z.xmin)))?,
                FpVar::new_input(cs.clone(), || Ok(F::from(z.xmax)))?,
                FpVar::new_input(cs.clone(), || Ok(F::from(z.ymin)))?,
                FpVar::new_input(cs.clone(), || Ok(F::from(z.ymax)))?,
            ])
        };
        let za = alloc_box(&self.zone_a)?;
        let zb = alloc_box(&self.zone_b)?;
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut ts = Vec::new();
        for p in &self.symbols {
            xs.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.x)))?);
            ys.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.y)))?);
            ts.push(FpVar::new_witness(cs.clone(), || Ok(F::from(p.t)))?);
        }
        let flat: Vec<FpVar<F>> = (0..xs.len())
            .flat_map(|i| [xs[i].clone(), ys[i].clone(), ts[i].clone()])
            .collect();
        enforce_commitment(cs.clone(), self.commit, &self.symbols, flat)?;

        // Native state trace, used only to assign witnesses.
        let mut native_s = 0usize;
        // Initial one-hot state: idle (constants, no constraints).
        let mut state: Vec<FpVar<F>> = (0..nq)
            .map(|q| if q == 0 { FpVar::one() } else { FpVar::zero() })
            .collect();

        for i in 0..self.symbols.len() {
            enforce_in_range(cs.clone(), &xs[i], COORD_BITS)?;
            enforce_in_range(cs.clone(), &ys[i], COORD_BITS)?;
            // Classification (sound: computed in-circuit from the point).
            let a = in_box(cs.clone(), &xs[i], &ys[i], &za, COORD_BITS)?;
            let b_raw = in_box(cs.clone(), &xs[i], &ys[i], &zb, COORD_BITS)?;
            // Four symbols: A only, B only, both, other (zones may overlap).
            let a_only = &a & &!&b_raw;
            let b_only = &b_raw & &!&a;
            let both = &a & &b_raw;
            let o = !&(&a | &b_raw);
            let sym = [(FpVar::from(a_only), true, false), (FpVar::from(b_only), false, true),
                (FpVar::from(both), true, true), (FpVar::from(o), false, false)];

            // Products p[q][c] = state[q] * sym[c]  -> nq * 4 constraints.
            let mut next: Vec<FpVar<F>> = vec![FpVar::zero(); nq];
            for q in 0..nq {
                for (sv, sa, sb) in sym.iter() {
                    let q2 = next_state(q, *sa, *sb, k, acc);
                    let prod = &state[q] * sv;
                    next[q2] += prod;
                }
            }
            // Materialise the next state as fresh witnesses (nq constraints),
            // so linear combinations do not grow across steps.
            let (ia, ib) = (self.zone_a.contains(&self.symbols[i]), self.zone_b.contains(&self.symbols[i]));
            native_s = next_state(native_s, ia, ib, k, acc);
            let mut fresh = Vec::with_capacity(nq);
            for q in 0..nq {
                let v = FpVar::new_witness(cs.clone(), || Ok(if q == native_s { F::one() } else { F::zero() }))?;
                v.enforce_equal(&next[q])?;
                fresh.push(v);
            }
            state = fresh;
        }
        state[acc].enforce_equal(&FpVar::one())?;
        Ok(())
    }
}

/// Exact R1CS constraint count of `BucketAutomatonCircuit` without a
/// commitment, for L >= 1 buckets and counter bound k. The first step is
/// cheaper because the initial one-hot state is constant. Checked against
/// synthesis in `tests/circuits.rs::cost_formulas_match_synthesis`.
/// Lets experiments price fine time resolutions without synthesizing
/// multi-million-constraint circuits.
pub fn b3_constraints(l: usize, k: usize) -> usize {
    assert!(l >= 1);
    (349 + k) + (l - 1) * (356 + 5 * k)
}
