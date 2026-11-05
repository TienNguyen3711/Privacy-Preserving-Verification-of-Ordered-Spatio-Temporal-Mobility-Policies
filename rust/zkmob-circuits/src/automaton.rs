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
//!
//! The end of this file holds the exact-time counterpart, BL-clockDFA
//! (`ClockDfaCircuit`): no buckets, one symbol per recorded fix and one
//! clock per step.

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
    use crate::types::COORD_BITS as C;
    assert!(l >= 1);
    // per bucket: x, y range checks + two box classifications, then the DFA step
    let classify = 2 * (C + 1) + 2 * (4 * (C + 2) + 3);
    (classify + 5 + k) + (l - 1) * (classify + 12 + 5 * k)
}

/// DA's conservative ("sound") variant: accept only if A and B fall in
/// buckets i < j with j - i <= k_sound = floor(gap / w) - 1. Any acceptance
/// then implies a true gap below (k_sound + 1) w <= gap, so it never proves a
/// false statement, at the price of more false negatives. Returns None when
/// k_sound < 1 (no window can be certified at this width).
pub fn sound_k(gap: u64, w: u64) -> Option<usize> {
    let k = (gap / w) as i64 - 1;
    (k >= 1).then_some(k as usize)
}

/// Lower bound on binding B3's buckets to the committed fixes. Any sound
/// B3 over a fix-signed trace must, for every fix, range-check it, classify
/// it into A and B, and place it in a bucket: t = q w + r with 0 <= r < w and
/// q non-decreasing. This circuit does exactly that and nothing else (it
/// omits aggregating fixes into per-bucket symbols and feeding the DFA), so
/// its constraint count is a lower bound on the binding cost.
#[derive(Clone)]
pub struct BucketBindingCircuit {
    pub traj: Vec<Point>,
    pub zone_a: BoxZone,
    pub zone_b: BoxZone,
    pub w: u64,
    pub horizon: u64,
}

fn bits_of(v: u64) -> usize { (64 - v.max(1).leading_zeros()) as usize }

impl<F: PrimeField> ConstraintSynthesizer<F> for BucketBindingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let alloc_box = |z: &BoxZone| -> Result<[FpVar<F>; 4], SynthesisError> {
            Ok([z.xmin, z.xmax, z.ymin, z.ymax].map(|v| FpVar::new_input(cs.clone(), || Ok(F::from(v))).unwrap()))
        };
        let (za, zb) = (alloc_box(&self.zone_a)?, alloc_box(&self.zone_b)?);
        let w = FpVar::constant(F::from(self.w));
        let wm1 = FpVar::constant(F::from(self.w - 1));
        let qbits = bits_of(self.horizon.div_ceil(self.w));
        let rbits = bits_of(self.w - 1);
        let mut prev_q: Option<FpVar<F>> = None;
        for p in &self.traj {
            let x = FpVar::new_witness(cs.clone(), || Ok(F::from(p.x)))?;
            let y = FpVar::new_witness(cs.clone(), || Ok(F::from(p.y)))?;
            let t = FpVar::new_witness(cs.clone(), || Ok(F::from(p.t)))?;
            enforce_in_range(cs.clone(), &x, COORD_BITS)?;
            enforce_in_range(cs.clone(), &y, COORD_BITS)?;
            enforce_in_range(cs.clone(), &t, TIME_BITS)?;
            let _a = in_box(cs.clone(), &x, &y, &za, COORD_BITS)?;
            let _b = in_box(cs.clone(), &x, &y, &zb, COORD_BITS)?;
            let q = FpVar::new_witness(cs.clone(), || Ok(F::from(p.t / self.w)))?;
            let r = FpVar::new_witness(cs.clone(), || Ok(F::from(p.t % self.w)))?;
            (&q * &w + &r).enforce_equal(&t)?;
            enforce_in_range(cs.clone(), &r, rbits)?;
            enforce_leq(cs.clone(), &r, &wm1, rbits)?;
            enforce_in_range(cs.clone(), &q, qbits)?;
            if let Some(pq) = &prev_q {
                enforce_leq(cs.clone(), pq, &q, qbits)?;
            }
            prev_q = Some(q);
        }
        Ok(())
    }
}

/// Exact constraint count of `BucketBindingCircuit` (checked in tests).
pub fn binding_constraints(n: usize, w: u64, horizon: u64) -> usize {
    use crate::types::{COORD_BITS as C, TIME_BITS as T};
    let qb = bits_of(horizon.div_ceil(w));
    let rb = bits_of(w - 1);
    // x, y, t ranges; two box checks; r range and r < w; q range (t = q w + r is linear)
    let per_fix = 2 * (C + 1) + (T + 1) + 2 * (4 * (C + 2) + 3) - 1 + (rb + 1) + (rb + 1) + (qb + 1);
    n * per_fix + n.saturating_sub(1) * (qb + 1)
}

// ---------------------------------------------------------------------------
// BL-clockDFA: the fair "automaton" baseline with exact time.
//
// Instead of discretising time into buckets, a deterministic timed automaton
// reads one symbol per recorded fix and keeps one clock per step. A clock is
// stored as the timestamp of its last reset, so "clock <= Delta" is the
// comparison t - c <= Delta on 17-bit integers (exact, no width w).
//
// States q = 0..=k count the steps matched so far (k = accept); with an
// Avoid zone there is one more, absorbing, reject state k + 1. Per fix:
//   adv_s = fix in zone_s AND (s = 0 OR t - c_{s-1} <= Delta_s)
//   reset c_s := t  when the automaton has matched >= s steps and adv_s
//   state q -> q + 1 on adv_q,  any non-reject state -> reject on Avoid
// Resetting c_s on every later admissible fix keeps the LATEST end of a
// partial match, which is optimal because gaps only bound t_j - t_i on a
// time-sorted trace; so the automaton decides `find_witness` exactly
// (tested in tests/circuits.rs against the reference semantics). The
// clock of the last step is never read, so it is not stored.
//
// The circuit uses one-hot states and materialises each next state as
// fresh witnesses, as `BucketAutomatonCircuit` does, and like the scan it
// proves either outcome (public: policy || outcome bit).

/// One BL-clockDFA step on fix `p` (the circuit assigns its state
/// witnesses with this function). `q = k + 1` is the reject state.
fn clock_dfa_step(q: &mut usize, clock: &mut [u64], p: &Point, steps: &[Step], avoid: Option<&BoxZone>) {
    let k = steps.len();
    if *q == k + 1 {
        return;
    }
    // wrapping_sub: on an unsorted trace the guard fails here, and the
    // circuit is unsatisfiable anyway (it enforces sorted time).
    let adv: Vec<bool> = (0..k)
        .map(|s| steps[s].zone.contains(p) && (s == 0 || steps[s].max_gap.is_none_or(|g| p.t.wrapping_sub(clock[s - 1]) <= g)))
        .collect();
    for s in 0..k {
        if *q >= s && adv[s] {
            clock[s] = p.t;
        }
    }
    if avoid.is_some_and(|z| z.contains(p)) {
        *q = k + 1;
    } else if *q < k && adv[*q] {
        *q += 1;
    }
}

/// Native BL-clockDFA run; returns the final state (k = accept, k + 1 =
/// reject on Avoid).
pub fn clock_dfa_run(traj: &[Point], steps: &[Step], avoid: Option<&BoxZone>) -> usize {
    let (mut q, mut clock) = (0usize, vec![0u64; steps.len()]);
    for p in traj {
        clock_dfa_step(&mut q, &mut clock, p, steps, avoid);
    }
    q
}

/// Native outcome of BL-clockDFA.
pub fn clock_dfa_accepts(traj: &[Point], steps: &[Step], avoid: Option<&BoxZone>) -> bool {
    clock_dfa_run(traj, steps, avoid) == steps.len()
}

/// BL-clockDFA circuit (public: policy || outcome), no commitment, so that
/// it is priced exactly like `budget::ScanPolicyCircuit`.
#[derive(Clone)]
pub struct ClockDfaCircuit {
    pub traj: Vec<Point>,
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
    pub outcome: bool,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ClockDfaCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        use crate::ordered::{alloc_policy, alloc_trajectory};
        let pol = alloc_policy(&cs, &self.steps, self.avoid.as_ref())?;
        let b = Boolean::new_input(cs.clone(), || Ok(self.outcome))?;
        let (xs, ys, ts) = alloc_trajectory(&cs, &self.traj)?;
        let k = self.steps.len();
        let reject = k + 1;
        let nq = if self.avoid.is_some() { k + 2 } else { k + 1 };

        let mut state: Vec<FpVar<F>> = (0..nq).map(|q| if q == 0 { FpVar::one() } else { FpVar::zero() }).collect();
        // Clock c_s for s < k - 1 (the last step's clock is never read).
        let mut clock: Vec<FpVar<F>> = vec![FpVar::zero(); k.saturating_sub(1)];
        let (mut native_q, mut native_clock) = (0usize, vec![0u64; k]);

        for j in 0..xs.len() {
            enforce_in_range(cs.clone(), &xs[j], COORD_BITS)?;
            enforce_in_range(cs.clone(), &ys[j], COORD_BITS)?;
            enforce_in_range(cs.clone(), &ts[j], TIME_BITS)?;
            if j > 0 {
                enforce_leq(cs.clone(), &ts[j - 1], &ts[j], TIME_BITS)?;
            }
            // Symbols and clock guards, all read from the clocks before this fix.
            let mut adv: Vec<FpVar<F>> = Vec::with_capacity(k);
            for s in 0..k {
                let inz = in_box(cs.clone(), &xs[j], &ys[j], &pol.zones[s], COORD_BITS)?;
                let a = match (s, &pol.gaps[s]) {
                    (0, _) | (_, None) => inz,
                    (_, Some(g)) => &inz & &is_leq(cs.clone(), &(&ts[j] - &clock[s - 1]), g, TIME_BITS)?,
                };
                adv.push(FpVar::from(a));
            }
            // Clock resets: c_s := t if at least s steps are matched and adv_s.
            for s in 0..k.saturating_sub(1) {
                // fold, not sum(): FpVar's Sum panics when every term is a constant
                let matched = (s..=k).fold(FpVar::zero(), |acc, q| acc + &state[q]);
                let hit = &matched * &adv[s];
                clock[s] = &clock[s] + &hit * (&ts[j] - &clock[s]);
            }
            // Transitions.
            let v = match &pol.avoid {
                Some(z) => Some(FpVar::from(in_box(cs.clone(), &xs[j], &ys[j], z, COORD_BITS)?)),
                None => None,
            };
            let mut next: Vec<FpVar<F>> = vec![FpVar::zero(); nq];
            for q in 0..=k {
                let to_reject = match &v {
                    Some(v) => &state[q] * v,
                    None => FpVar::zero(),
                };
                let rest = &state[q] - &to_reject;
                let advance = if q < k { &rest * &adv[q] } else { FpVar::zero() };
                if v.is_some() {
                    next[reject] += &to_reject;
                }
                if q < k {
                    next[q + 1] += &advance;
                }
                next[q] += rest - advance;
            }
            if v.is_some() {
                next[reject] += &state[reject];
            }
            clock_dfa_step(&mut native_q, &mut native_clock, &self.traj[j], &self.steps, self.avoid.as_ref());
            let mut fresh = Vec::with_capacity(nq);
            for q in 0..nq {
                let w = FpVar::new_witness(cs.clone(), || Ok(if q == native_q { F::one() } else { F::zero() }))?;
                w.enforce_equal(&next[q])?;
                fresh.push(w);
            }
            state = fresh;
        }
        state[k].enforce_equal(&FpVar::from(b))
    }
}

/// Exact R1CS constraint count of `ClockDfaCircuit` for n >= 1 fixes, k
/// steps of which `gapped` carry a max_gap, with or without an Avoid zone.
/// Fitted on synthesized circuits and checked against synthesis over a grid
/// of shapes in `tests/clock_dfa.rs::clock_cost_formula_matches_synthesis`.
/// Per later fix: range checks and time order (70), k zone tests, a guard
/// per gap, the clock resets and the one-hot transition; the first fix has
/// no time-order check and a constant initial state.
pub fn clock_constraints(n: usize, k: usize, gapped: usize, avoid: bool) -> usize {
    assert!(n >= 1 && k >= 1 && gapped < k);
    let (first, per_fix) = if avoid {
        (129 + 77 * k + 20 * gapped, 145 + 79 * k + 20 * gapped)
    } else {
        (54 + 76 * k + 20 * gapped, 69 + 78 * k + 20 * gapped)
    };
    first + (n - 1) * per_fix
}
